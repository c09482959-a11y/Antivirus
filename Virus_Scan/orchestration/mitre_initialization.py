"""Canonical startup boundary for the persistent external ATT&CK cache."""
from __future__ import annotations

from pathlib import Path, PosixPath, WindowsPath

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.detection.attack.activation import build_attack_activation_record
from Virus_Scan.detection.attack.cache import (
    active_bundle_path, bundle_identity_from_path, cache_paths,
    ensure_generated_controls, load_state,
)
from Virus_Scan.detection.attack.config import AttackConfig, load_config
from Virus_Scan.detection.attack.download import (
    activate_packaged_seed_repository, refresh_repository,
)
from Virus_Scan.detection.attack.integrity import verify_git_blob_identity
from Virus_Scan.detection.attack.stix_importer import import_stix_bundle
from Virus_Scan.runtime.api import (
    ResourceLockSet, configure_mitre_runtime, mitre_dir, resource_root_snapshot,
)

_MAX_LOCAL_CANDIDATES = 16
_PATH_TYPES = (Path, PosixPath, WindowsPath)


def _arg(args: object, name: str, default: object = None) -> object:
    data = no_hook_plain_instance_dict(args)
    if data is not None:
        return dict.get(data, name, default)
    return default


def _config_from_args(args: object, root: Path) -> AttackConfig:
    config_path = _arg(args, "mitre_config")
    expected = (root / "mitre_config.toml").resolve()
    if type(config_path) is str and config_path:
        resolved = Path(config_path).expanduser().resolve()
        if resolved != expected:
            raise ValueError("mitre_config_path_outside_resource_root")
        config = load_config(resolved)
    else:
        config = AttackConfig()
    enabled = config.enabled and _arg(args, "no_mitre", False) is not True
    force_refresh = config.force_refresh or _arg(args, "mitre_force_refresh", False) is True
    no_download = _arg(args, "mitre_no_download", False) is True
    if no_download and force_refresh:
        raise ValueError("mitre_force_refresh_conflicts_with_no_download")
    allow_download = False if no_download else (config.allow_download or force_refresh)
    api_url = _arg(args, "mitre_api_url")
    ref = _arg(args, "mitre_ref")
    return AttackConfig(
        enabled=enabled, allow_download=allow_download, force_refresh=force_refresh,
        api_url=api_url if type(api_url) is str and api_url else config.api_url,
        ref=ref if type(ref) is str and ref else config.ref,
        maximum_bytes=config.maximum_bytes,
    )


def _read_local_bundle(bundle: Path, maximum_bytes: int) -> bytes:
    if type(maximum_bytes) is not int or type(maximum_bytes) is bool:
        raise TypeError("mitre_local_bundle_limit_invalid")
    with bundle.open("rb") as handle:
        payload = handle.read(maximum_bytes + 1)
    if len(payload) < 1 or len(payload) > maximum_bytes:
        raise ValueError("mitre_local_bundle_size_invalid")
    return payload


def _load_bundle(bundle: Path, maximum_bytes: int):
    expected = bundle_identity_from_path(bundle)
    if expected is None:
        raise ValueError("mitre_local_bundle_identity_invalid")
    payload = _read_local_bundle(bundle, maximum_bytes)
    computed, local_sha256 = verify_git_blob_identity(payload, expected)
    snapshot = import_stix_bundle(
        payload, dataset_version=expected, source_ref="offline-cache",
        expected_git_blob_sha1=expected, computed_git_blob_sha1=computed,
        local_sha256=local_sha256,
    )
    return snapshot, expected, computed, local_sha256


def _local_candidates(root: Path, state: dict[str, object] | None) -> tuple[Path, ...]:
    active = active_bundle_path(root, state)
    discovered = tuple(sorted(
        path for path in root.glob("enterprise-attack-v*.json")
        if bundle_identity_from_path(path) is not None
    ))
    if active is None:
        return discovered
    return (active, *(path for path in discovered if path != active))


def _load_local(root: Path, state: dict[str, object] | None, maximum_bytes: int):
    candidates = _local_candidates(root, state)
    if not candidates or len(candidates) > _MAX_LOCAL_CANDIDATES:
        return None, None, None
    active = active_bundle_path(root, state)
    valid: list[tuple[object, dict[str, object], Path]] = []
    for bundle in candidates:
        try:
            snapshot, expected, computed, local_sha256 = _load_bundle(bundle, maximum_bytes)
        except (OSError, ValueError, TypeError, UnicodeError):
            continue
        source = "offline_active_cache" if bundle == active else "offline_last_known_good_cache"
        activation = build_attack_activation_record(snapshot)
        record = {
            "active_cache_source": source,
            "api_identity_checked": False,
            "sha1_verification_state": "local_git_blob_recomputed",
            "expected_git_blob_sha1": expected,
            "computed_git_blob_sha1": computed,
            "local_sha256": local_sha256,
            "integrity_state": "semantic_and_local_integrity_valid",
            "activation_state": "revalidated_from_local_cache",
            "activation_digest": activation.activation_digest,
            "activation_counts": activation.counts(),
            "unavailable_reason": "",
        }
        if bundle == active:
            return snapshot, record, bundle
        valid.append((snapshot, record, bundle))
    if len(valid) != 1:
        return None, None, None
    return valid[0]




def _is_readonly_worker(args: object) -> bool:
    scheduler = _arg(args, "scheduler", "")
    return type(scheduler) is str and str.__eq__(scheduler, "queue-child")


def _acquire_existing_read_locks(
    lock_set: ResourceLockSet,
    paths: tuple[Path, ...],
) -> None:
    if type(lock_set) is not ResourceLockSet or type(paths) is not tuple:
        raise TypeError("mitre_worker_lock_contract_invalid")
    for path in paths:
        if type(path) not in _PATH_TYPES:
            raise TypeError("mitre_worker_lock_path_invalid")
        if path.is_file():
            lock_set.acquire(path, writable=False)


def _initialize_readonly_repository(root: Path):
    if type(root) not in _PATH_TYPES:
        raise TypeError("mitre_worker_root_invalid")
    lock_set = ResourceLockSet()
    paths = cache_paths(root)
    try:
        _acquire_existing_read_locks(
            lock_set,
            (paths["config"], paths["schema"], paths["readme"], paths["notice"], paths["state"], paths["index"]),
        )
        state = load_state(paths["state"])
        candidates = _local_candidates(root, state)
        if not candidates or len(candidates) > _MAX_LOCAL_CANDIDATES:
            lock_set.release_all()
            return _configure_unavailable("mitre_worker_repository_unavailable", enabled=True, lock_set=None)
        _acquire_existing_read_locks(lock_set, candidates)
        snapshot, local_status, _active_bundle = _load_local(root, state, AttackConfig().maximum_bytes)
        if snapshot is None or local_status is None:
            lock_set.release_all()
            return _configure_unavailable("mitre_worker_repository_unavailable", enabled=True, lock_set=None)
        status = {
            **local_status,
            "config_state": "parent_validated_readonly",
            "refresh_state": "worker_readonly",
            "object_counts": dict(snapshot.object_counts),
            "dataset_version": snapshot.version.dataset_version,
            "repository_digest": snapshot.digest,
        }
        return configure_mitre_runtime(snapshot, enabled=True, status=status, lock_set=lock_set)
    except (OSError, ValueError, TypeError, UnicodeError):
        lock_set.release_all()
        return _configure_unavailable("mitre_worker_initialization_failed", enabled=True, lock_set=None)


def initialize_mitre_worker_runtime(
    *,
    root: str,
    enabled: bool,
    available: bool,
    expected_repository_digest: str,
    expected_dataset_version: str,
    unavailable_reason: str,
):
    """Configure one spawned scheduler worker from the parent-approved MITRE state."""
    if type(enabled) is not bool or type(available) is not bool:
        raise TypeError("mitre_worker_runtime_flags_invalid")
    if type(root) is not str or root == "" or len(root) > 4096:
        raise ValueError("mitre_worker_runtime_root_invalid")
    if type(expected_repository_digest) is not str or type(expected_dataset_version) is not str:
        raise TypeError("mitre_worker_runtime_identity_invalid")
    if type(unavailable_reason) is not str or len(unavailable_reason) > 256:
        raise ValueError("mitre_worker_runtime_reason_invalid")
    if not available:
        if expected_repository_digest != "" or expected_dataset_version != "":
            raise ValueError("mitre_worker_unavailable_identity_present")
        reason = unavailable_reason or ("mitre_disabled" if not enabled else "mitre_parent_repository_unavailable")
        return _configure_unavailable(reason, enabled=enabled, lock_set=None)
    if not enabled:
        raise ValueError("mitre_worker_available_while_disabled")
    if len(expected_repository_digest) != 64 or len(expected_dataset_version) != 40:
        raise ValueError("mitre_worker_expected_identity_invalid")
    worker = _initialize_readonly_repository(Path(root).expanduser().resolve())
    if not worker.available or worker.repository is None:
        raise RuntimeError("mitre_worker_required_repository_unavailable")
    if worker.repository.digest != expected_repository_digest:
        raise RuntimeError("mitre_worker_repository_digest_mismatch")
    if worker.repository.version.dataset_version != expected_dataset_version:
        raise RuntimeError("mitre_worker_dataset_version_mismatch")
    return worker


def _initialize_readonly_worker(args: object, root: Path):
    if _arg(args, "no_mitre", False) is True:
        return _configure_unavailable("mitre_disabled", enabled=False, lock_set=None)
    return _initialize_readonly_repository(root)


def _configure_unavailable(reason: str, *, enabled: bool, lock_set: ResourceLockSet | None):
    status = {
        "unavailable_reason": reason,
        "config_state": "unavailable", "refresh_state": "not_run",
    }
    return configure_mitre_runtime(None, enabled=enabled, status=status, lock_set=lock_set)


def initialize_mitre_from_args(args: object):
    if _arg(args, "no_mitre", False) is True:
        return _configure_unavailable("mitre_disabled", enabled=False, lock_set=None)
    root = mitre_dir()
    if _is_readonly_worker(args):
        return _initialize_readonly_worker(args, root)
    lock_set = ResourceLockSet()
    paths = cache_paths(root)
    try:
        lock_set.acquire(paths["lock"], writable=True)
    except (OSError, TypeError, ValueError):
        return _configure_unavailable("mitre_lock_unavailable", enabled=True, lock_set=None)
    try:
        ensure_generated_controls(root)
        config = _config_from_args(args, root)
        explicit_config = type(_arg(args, "mitre_config")) is str and bool(_arg(args, "mitre_config"))
        if not config.enabled:
            return _configure_unavailable("mitre_disabled", enabled=False, lock_set=lock_set)
        state = load_state(paths["state"])
        snapshot = None
        status: dict[str, object] = {"unavailable_reason": "mitre_repository_unavailable"}
        active_bundle = None
        if config.allow_download and (config.force_refresh or state is None):
            try:
                snapshot, refresh_state, active_bundle = refresh_repository(root, config)
                status = {
                    **refresh_state, "active_cache_source": "github_contents_api",
                    "api_identity_checked": True, "sha1_verification_state": "verified",
                    "integrity_state": "verified_and_semantically_valid",
                    "refresh_state": "refreshed", "unavailable_reason": "",
                }
            except (OSError, ValueError, TypeError, UnicodeError):
                snapshot, local_status, active_bundle = _load_local(
                    root, state, config.maximum_bytes,
                )
                if local_status is not None:
                    status = {
                        **local_status,
                        "refresh_failure": "last_known_good_retained",
                        "refresh_state": "failed_lkg_retained",
                    }
                else:
                    status = {
                        "unavailable_reason": "mitre_refresh_and_local_cache_failed",
                        "refresh_state": "failed",
                    }
        else:
            snapshot, local_status, active_bundle = _load_local(
                root, state, config.maximum_bytes,
            )
            if local_status is not None:
                status = {**local_status, "refresh_state": "not_requested"}
            else:
                try:
                    roots = resource_root_snapshot()
                    if Path(roots.mitre_root) != root.resolve(strict=False):
                        raise ValueError("mitre_resource_snapshot_root_mismatch")
                    snapshot, seed_state, active_bundle = activate_packaged_seed_repository(
                        root, Path(roots.mitre_seed_path), maximum_bytes=config.maximum_bytes,
                    )
                    status = {
                        "active_cache_source": "validated_offline_seed",
                        "api_identity_checked": False,
                        "sha1_verification_state": "packaged_seed_identity_verified",
                        "expected_git_blob_sha1": seed_state["expected_git_blob_sha1"],
                        "computed_git_blob_sha1": seed_state["computed_git_blob_sha1"],
                        "local_sha256": seed_state["local_sha256"],
                        "integrity_state": "verified_and_semantically_valid",
                        "source_ref": seed_state["source_ref"],
                        "activation_state": seed_state["activation_state"],
                        "activation_digest": seed_state["activation_digest"],
                        "activation_counts": seed_state["activation_counts"],
                        "refresh_state": "seed_activated",
                        "unavailable_reason": "",
                    }
                except (OSError, ValueError, TypeError, UnicodeError) as exc:
                    status = {
                        "unavailable_reason": "mitre_repository_unavailable",
                        "refresh_state": "not_requested",
                    }
        for path in (
            paths["config"], paths["defaults"], paths["schema"], paths["readme"], paths["notice"],
            paths["state"], paths["index"], active_bundle,
        ):
            if type(path) in _PATH_TYPES and path.is_file():
                lock_set.acquire(path, writable=False)
        status["config_state"] = "explicit_validated_toml" if explicit_config else "typed_defaults"
        if snapshot is not None:
            status["object_counts"] = dict(snapshot.object_counts)
            status["dataset_version"] = snapshot.version.dataset_version
            status["repository_digest"] = snapshot.digest
        return configure_mitre_runtime(snapshot, enabled=True, status=status, lock_set=lock_set)
    except (OSError, ValueError, TypeError, UnicodeError):
        lock_set.release_all()
        return _configure_unavailable("mitre_initialization_failed", enabled=True, lock_set=None)


__all__ = ("initialize_mitre_from_args", "initialize_mitre_worker_runtime")
