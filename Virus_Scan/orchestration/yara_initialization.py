"""Canonical startup boundary for generated YARA controls and rule loading."""
from __future__ import annotations

import json
import logging
from pathlib import Path, PosixPath, WindowsPath
from types import SimpleNamespace

from Virus_Scan.contracts.no_hook_materialization import (
    materialize_json_no_hook,
    no_hook_plain_instance_dict,
)
from Virus_Scan.runtime.api import (
    ResourceLockSet,
    RuntimeContext,
    configure_deep_scan_mode,
    path_contains_filesystem_alias,
    program_root,
    yara_dir,
    yara_rules_state,
)
from Virus_Scan.yara.config import YaraConfig, load_config
from Virus_Scan.yara.control_files import control_paths, ensure_generated_controls
from Virus_Scan.yara.download import official_state_path
from Virus_Scan.yara.execution_identity import selected_yara_execution_provenance
from Virus_Scan.yara.execution_policy import (
    selected_yara_snapshot,
    selected_yara_snapshot_ready,
    yara_light_selected,
)
import Virus_Scan.yara.loader as yara_loader
from Virus_Scan.yara.phase_contracts import yara_parallel_group_count
from Virus_Scan.yara.publication import disabled_package_status, load_attempt_status
from Virus_Scan.yara.versioning import YARA_CONFIG_VERSION

_PATH_TYPES = (Path, PosixPath, WindowsPath)


def _arg(args: object, name: str, default: object = None) -> object:
    data = no_hook_plain_instance_dict(args)
    if data is not None:
        return dict.get(data, name, default)
    return default


def _exact_flag(args: object, name: str) -> bool:
    return _arg(args, name, False) is True


def _is_readonly_worker(args: object) -> bool:
    scheduler = _arg(args, "scheduler", "")
    return type(scheduler) is str and str.__eq__(scheduler, "queue-child")


def _config_from_args(args: object, root: Path) -> YaraConfig:
    config_path = _arg(args, "yara_config")
    if type(config_path) is str and config_path:
        resolved = Path(config_path).expanduser().resolve()
        expected = (root / "yara_config.toml").resolve()
        if resolved != expected:
            raise ValueError("yara_config_path_outside_resource_root")
        config = load_config(resolved)
    else:
        config = YaraConfig()
    force_refresh = config.force_refresh or _exact_flag(args, "yara_force_refresh")
    light_selected = yara_light_selected(_arg(args, "deep_scan_mode", "auto"))
    full_enabled = config.full_enabled and not light_selected
    light_enabled = (
        config.light_enabled
        and light_selected
        and not _exact_flag(args, "no_yaralight")
    )
    full_no_download = _exact_flag(args, "yara_no_download")
    light_no_download = _exact_flag(args, "yaralight_no_download")
    if force_refresh and (
        (full_enabled and full_no_download)
        or (light_enabled and light_no_download)
    ):
        raise ValueError("yara_force_refresh_conflicts_with_no_download")
    return YaraConfig(
        enabled=config.enabled,
        full_enabled=full_enabled,
        light_enabled=light_enabled,
        allow_full_download=(
            False
            if full_no_download
            else config.allow_full_download
            or force_refresh
        ),
        allow_light_download=(
            False if light_no_download else config.allow_light_download or force_refresh
        ),
        force_refresh=force_refresh,
        release_api_url=config.release_api_url,
        partial_compile_threshold=config.partial_compile_threshold,
        maximum_archive_bytes=config.maximum_archive_bytes,
        maximum_manifest_bytes=config.maximum_manifest_bytes,
        maximum_members=config.maximum_members,
        maximum_total_uncompressed_bytes=config.maximum_total_uncompressed_bytes,
        maximum_member_bytes=config.maximum_member_bytes,
        maximum_compression_ratio=config.maximum_compression_ratio,
        full_expected_sha256=config.full_expected_sha256,
        light_expected_sha256=config.light_expected_sha256,
        custom_rule_expected_sha256=config.custom_rule_expected_sha256,
    )


def _acquire_existing_read_locks(
    lock_set: ResourceLockSet,
    paths: tuple[Path, ...],
) -> None:
    if type(lock_set) is not ResourceLockSet or type(paths) is not tuple:
        raise TypeError("yara_runtime_lock_contract_invalid")
    existing = {path.resolve() for path in lock_set.paths}
    for path in paths:
        if type(path) not in _PATH_TYPES:
            raise TypeError("yara_runtime_lock_path_invalid")
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in existing:
            continue
        lock_set.acquire(path, writable=False)
        existing.add(resolved)


def _attempt_paths(
    attempts: tuple[yara_loader.YaraLoadAttempt | None, ...],
) -> tuple[Path, ...]:
    if type(attempts) is not tuple:
        raise TypeError("yara_runtime_attempts_invalid")
    paths: list[Path] = []
    for attempt in attempts:
        if attempt is None:
            continue
        if type(attempt) is not yara_loader.YaraLoadAttempt:
            raise TypeError("yara_runtime_attempt_invalid")
        paths.extend(yara_loader.load_attempt_resource_paths(attempt))
    return tuple(paths)


def _config_status(
    args: object,
    *,
    config: YaraConfig | None,
    root: Path | None,
    use_cache: bool,
    readonly: bool,
    unavailable_reason: str,
) -> dict[str, object]:
    if config is not None and type(config) is not YaraConfig:
        raise TypeError("yara_publication_config_invalid")
    explicit = _arg(args, "yara_config")
    source = (
        "explicit_validated_toml"
        if type(explicit) is str and explicit and config is not None
        else "explicit_config_invalid"
        if type(explicit) is str and explicit
        else "typed_defaults"
        if config is not None
        else "not_loaded"
    )
    return {
        "config_path": "" if root is None else str(root / "yara_config.toml"),
        "config_schema_version": YARA_CONFIG_VERSION,
        "config_source": source,
        "full_auto_download": False if config is None else config.allow_full_download,
        "full_enabled": False if config is None else config.full_enabled,
        "full_expected_sha256": "" if config is None else config.full_expected_sha256,
        "light_auto_download": False if config is None else config.allow_light_download,
        "light_enabled": False if config is None else config.light_enabled,
        "light_expected_sha256": "" if config is None else config.light_expected_sha256,
        "custom_rule_expected_sha256": "" if config is None else config.custom_rule_expected_sha256,
        "release_api_url": "" if config is None else config.release_api_url,
        "resource_root": "" if root is None else str(root),
        "use_cache": use_cache,
        "worker_readonly": readonly,
        "unavailable_reason": unavailable_reason,
    }


def _publish_unavailable(
    args: object,
    *,
    enabled: bool,
    reason: str,
    config: YaraConfig | None = None,
    root: Path | None = None,
    readonly: bool = False,
) -> None:
    state = yara_rules_state()
    state.configure_runtime(
        enabled=enabled,
        config_status=_config_status(
            args,
            config=config,
            root=root,
            use_cache=False,
            readonly=readonly,
            unavailable_reason=reason,
        ),
        primary_status=disabled_package_status(reason),
        light_status=disabled_package_status(reason),
        lock_set=None,
        readonly=readonly,
    )


def _log_status_if_requested(args: object) -> None:
    if not _exact_flag(args, "yara_status"):
        return
    materialized = materialize_json_no_hook(
        yara_rules_state().runtime_snapshot().status,
        context="yara_runtime_status_log",
        max_depth=8,
        max_items=2048,
    )
    logging.info(
        "YARA status %s",
        json.dumps(materialized, sort_keys=True, separators=(",", ":"), allow_nan=False),
    )


def _clear_runtime_state(runtime: RuntimeContext) -> None:
    state = yara_rules_state()
    state.release_runtime()
    runtime.set("YARALIGHT_ENABLED", False)
    runtime.set("YARALIGHT_AUTO_DOWNLOAD", False)


def initialize_yara_from_args(runtime: RuntimeContext, args: object) -> tuple[object, bool]:
    if type(runtime) is not RuntimeContext:
        raise TypeError("yara_initialization_runtime_owner_invalid")
    _clear_runtime_state(runtime)
    if _exact_flag(args, "no_yara"):
        _publish_unavailable(args, enabled=False, reason="yara_disabled")
        _log_status_if_requested(args)
        logging.info("YARA disabled by --no-yara")
        return None, False

    readonly = _is_readonly_worker(args)
    root = (Path(program_root()) / "Yara") if readonly else Path(yara_dir())
    if readonly and (
        path_contains_filesystem_alias(root) or not root.is_dir()
    ):
        _publish_unavailable(
            args,
            enabled=True,
            reason="yara_worker_resources_unavailable",
            root=root,
            readonly=True,
        )
        _log_status_if_requested(args)
        logging.error("YARA read-only worker resources unavailable")
        return None, False
    if path_contains_filesystem_alias(root):
        _publish_unavailable(
            args,
            enabled=True,
            reason="yara_resource_root_rejected",
            root=root,
            readonly=readonly,
        )
        _log_status_if_requested(args)
        logging.error("YARA resource root rejected")
        return None, False

    lock_set = ResourceLockSet()
    controls = control_paths(root)
    config: YaraConfig | None = None
    try:
        if readonly:
            _acquire_existing_read_locks(
                lock_set,
                (
                    controls["config"],
                    controls["defaults"],
                    controls["schema"],
                    controls["readme"],
                    controls["manifest"],
                    official_state_path(root, "extended"),
                    official_state_path(root, "core"),
                ),
            )
        else:
            lock_set.acquire(controls["lock"], writable=True)
            controls = ensure_generated_controls(root)

        config = _config_from_args(args, root)
        if not config.enabled:
            lock_set.release_all()
            _publish_unavailable(
                args,
                enabled=False,
                reason="yara_disabled_by_config",
                config=config,
                root=root,
                readonly=readonly,
            )
            _log_status_if_requested(args)
            logging.info("YARA disabled by explicit configuration")
            return None, False

        use_cache = not _exact_flag(args, "yara_no_cache")
        full_attempt = (
            yara_loader.load_yara_rules(
                rule_path=_arg(args, "yara"),
                auto_download=False if readonly else config.allow_full_download,
                use_cache=use_cache,
                force_refresh=False if readonly else config.force_refresh,
                config=config,
                allow_cache_write=not readonly,
            )
            if config.full_enabled
            else None
        )

        runtime.set("YARALIGHT_ENABLED", config.light_enabled)
        runtime.set(
            "YARALIGHT_AUTO_DOWNLOAD",
            config.allow_light_download and not readonly,
        )
        light_attempt = (
            yara_loader.load_yaralight_rules(
                rule_path=_arg(args, "yaralight"),
                auto_download=False if readonly else config.allow_light_download,
                use_cache=use_cache,
                force_refresh=False if readonly else config.force_refresh,
                config=config,
                allow_cache_write=not readonly,
            )
            if config.light_enabled
            else None
        )
        if not config.light_enabled:
            yara_rules_state().set_light_rules(None, False, loaded_count=0)
            logging.info("YARA-light disabled")

        group_attempts: tuple[yara_loader.YaraLoadAttempt, ...] = ()
        if (
            not readonly
            and use_cache
            and full_attempt is not None
            and full_attempt.load_result.ready
            and full_attempt.source is not None
        ):
            group_count = yara_parallel_group_count(str(full_attempt.source.path))
            group_attempts = yara_loader.prepare_rule_group_caches(
                full_attempt.source,
                config,
                group_count,
                use_cache=True,
            )

        _acquire_existing_read_locks(
            lock_set,
            (
                controls["config"],
                controls["defaults"],
                controls["schema"],
                controls["readme"],
                controls["manifest"],
                *_attempt_paths((full_attempt, light_attempt, *group_attempts)),
            ),
        )
        if not lock_set.paths:
            raise OSError("yara_runtime_lock_set_unavailable")

        yara_rules_state().configure_runtime(
            enabled=True,
            config_status=_config_status(
                args,
                config=config,
                root=root,
                use_cache=use_cache,
                readonly=readonly,
                unavailable_reason="",
            ),
            primary_status=load_attempt_status(
                full_attempt,
                disabled_reason="yara_full_disabled",
                group_attempts=group_attempts,
            ),
            light_status=load_attempt_status(
                light_attempt,
                disabled_reason="yaralight_disabled",
            ),
            lock_set=lock_set,
            readonly=readonly,
        )
        _log_status_if_requested(args)
        selected = selected_yara_snapshot(
            yara_rules_state(),
            scan_mode=_arg(args, "deep_scan_mode", "auto"),
        )
        ready = selected_yara_snapshot_ready(selected)
        return (selected, True) if ready else (None, False)
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError) as error:
        try:
            lock_set.release_all()
        except OSError as release_error:
            logging.error("YARA lock release failed: %s", release_error)
        _clear_runtime_state(runtime)
        reason = "yara_initialization_failed:" + type(error).__name__
        _publish_unavailable(
            args,
            enabled=True,
            reason=reason,
            config=config,
            root=root,
            readonly=readonly,
        )
        _log_status_if_requested(args)
        logging.error("YARA initialization failed: %s", error)
        return None, False


def initialize_yara_worker_runtime(
    *,
    root: str,
    enabled: bool,
    available: bool,
    scan_mode: str,
    package_kind: str,
    source_path: str,
    expected_source_digest: str,
    expected_compiled_cache_digest: str,
    expected_rule_catalog_digest: str,
    unavailable_reason: str,
):
    """Initialize one spawned worker from the parent-approved YARA identity."""
    if type(enabled) is not bool or type(available) is not bool:
        raise TypeError("yara_worker_runtime_flags_invalid")
    if type(root) is not str or root == "" or len(root) > 4096:
        raise ValueError("yara_worker_runtime_root_invalid")
    if type(scan_mode) is not str or scan_mode == "" or len(scan_mode) > 32:
        raise ValueError("yara_worker_scan_mode_invalid")
    if type(package_kind) is not str or package_kind not in ("", "core", "extended"):
        raise ValueError("yara_worker_package_kind_invalid")
    for value, reason, maximum in (
        (source_path, "yara_worker_source_path_invalid", 4096),
        (unavailable_reason, "yara_worker_unavailable_reason_invalid", 256),
    ):
        if type(value) is not str or len(value) > maximum:
            raise ValueError(reason)
    for value, reason in (
        (expected_source_digest, "yara_worker_source_digest_invalid"),
        (expected_compiled_cache_digest, "yara_worker_cache_digest_invalid"),
        (expected_rule_catalog_digest, "yara_worker_catalog_digest_invalid"),
    ):
        if type(value) is not str:
            raise TypeError(reason)
    runtime_root = Path(root).expanduser().resolve()
    if runtime_root != Path(yara_dir()).resolve():
        raise RuntimeError("yara_worker_runtime_root_mismatch")
    configure_deep_scan_mode(scan_mode)
    runtime = RuntimeContext()
    _clear_runtime_state(runtime)
    if not available:
        if any((package_kind != "", source_path != "", expected_source_digest != "",
                expected_compiled_cache_digest != "", expected_rule_catalog_digest != "")):
            raise ValueError("yara_worker_unavailable_identity_present")
        reason = unavailable_reason or ("yara_disabled" if not enabled else "yara_parent_rules_unavailable")
        args = SimpleNamespace(no_yara=not enabled, deep_scan_mode=scan_mode, scheduler="queue-child")
        _publish_unavailable(args, enabled=enabled, reason=reason, root=runtime_root, readonly=True)
        return yara_rules_state().runtime_snapshot()
    if not enabled:
        raise ValueError("yara_worker_available_while_disabled")
    if package_kind not in ("core", "extended") or source_path == "":
        raise ValueError("yara_worker_available_identity_invalid")
    if any(len(value) != 64 for value in (
        expected_source_digest, expected_compiled_cache_digest, expected_rule_catalog_digest,
    )):
        raise ValueError("yara_worker_expected_identity_invalid")
    source_candidate = Path(source_path).expanduser().absolute()
    if (
        path_contains_filesystem_alias(source_candidate)
        or not source_candidate.is_file()
    ):
        raise RuntimeError("yara_worker_source_unavailable")
    source = source_candidate.resolve()
    config = YaraConfig(
        enabled=True,
        full_enabled=package_kind == "extended",
        light_enabled=package_kind == "core",
        allow_full_download=False,
        allow_light_download=False,
        full_expected_sha256=expected_source_digest if package_kind == "extended" else "",
        light_expected_sha256=expected_source_digest if package_kind == "core" else "",
    )
    runtime.set("YARALIGHT_ENABLED", package_kind == "core")
    runtime.set("YARALIGHT_AUTO_DOWNLOAD", False)
    lock_set = ResourceLockSet()
    args = SimpleNamespace(
        no_yara=False,
        deep_scan_mode=scan_mode,
        scheduler="queue-child",
        yara=str(source) if package_kind == "extended" else None,
        yaralight=str(source) if package_kind == "core" else None,
    )
    try:
        attempt = (
            yara_loader.load_yaralight_rules(
                rule_path=str(source), auto_download=False, use_cache=True,
                force_refresh=False, config=config, allow_cache_write=False,
            )
            if package_kind == "core"
            else yara_loader.load_yara_rules(
                rule_path=str(source), auto_download=False, use_cache=True,
                force_refresh=False, config=config, allow_cache_write=False,
            )
        )
        if not attempt.load_result.ready:
            raise RuntimeError("yara_worker_required_rules_unavailable:" + attempt.load_result.state)
        selected = selected_yara_snapshot(yara_rules_state(), scan_mode=scan_mode)
        if not selected_yara_snapshot_ready(selected):
            raise RuntimeError("yara_worker_selected_snapshot_unavailable")
        provenance = selected_yara_execution_provenance(selected)
        if not provenance.verified:
            raise RuntimeError("yara_worker_selected_snapshot_unverified")
        if provenance.package_kind != package_kind:
            raise RuntimeError("yara_worker_package_kind_mismatch")
        if provenance.source_digest != expected_source_digest:
            raise RuntimeError("yara_worker_source_digest_mismatch")
        if provenance.compiled_cache_digest != expected_compiled_cache_digest:
            raise RuntimeError("yara_worker_compiled_cache_digest_mismatch")
        if provenance.rule_catalog_digest != expected_rule_catalog_digest:
            raise RuntimeError("yara_worker_rule_catalog_digest_mismatch")
        _acquire_existing_read_locks(lock_set, (source, *_attempt_paths((attempt,))))
        if not lock_set.paths:
            raise RuntimeError("yara_worker_lock_set_unavailable")
        primary_attempt = attempt if package_kind == "extended" else None
        light_attempt = attempt if package_kind == "core" else None
        yara_rules_state().configure_runtime(
            enabled=True,
            config_status=_config_status(
                args, config=config, root=runtime_root, use_cache=True,
                readonly=True, unavailable_reason="",
            ),
            primary_status=load_attempt_status(primary_attempt, disabled_reason="yara_full_disabled"),
            light_status=load_attempt_status(light_attempt, disabled_reason="yaralight_disabled"),
            lock_set=lock_set,
            readonly=True,
        )
        return selected
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        lock_set.release_all()
        _clear_runtime_state(runtime)
        raise


__all__ = ("initialize_yara_from_args", "initialize_yara_worker_runtime")
