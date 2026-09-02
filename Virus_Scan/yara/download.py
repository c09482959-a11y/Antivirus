"""Canonical official YARA Forge acquisition and local revalidation owner."""
from __future__ import annotations

from pathlib import Path, PosixPath, WindowsPath
import urllib.error

from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraArchiveAcquisition, YaraArchiveSnapshot, YaraReleaseIdentity
from Virus_Scan.yara.download_io import (
    atomic_bytes, atomic_json, atomic_promote, download_archive_temp,
    load_json_state, request_bytes, require_real_directory,
)
from Virus_Scan.yara.integrity import bytes_sha256, file_sha256, parse_release_manifest
from Virus_Scan.yara.release_api import select_release_identity
from Virus_Scan.yara.rule_archive import validate_rule_archive
from Virus_Scan.yara.validation import package_kind, sha256_text

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_STATE_VERSION = "yara_archive_state_v2"


def official_state_path(root: Path, kind: str) -> Path:
    return root / ("yara_" + package_kind(kind) + "_state.json")


def official_artifact_paths(root: Path, identity: YaraReleaseIdentity, manifest_sha256: str) -> tuple[Path, Path]:
    digest = sha256_text(manifest_sha256, "yara_state_manifest_sha256_invalid")
    suffix = identity.release_tag + "-" + digest[:16]
    archive = root / ("yara-forge-rules-" + identity.package_kind + "-" + suffix + ".zip")
    manifest = root / ("yara-forge-rules-sha256-" + suffix + ".txt")
    return archive, manifest


def _identity_from_state(state: dict[str, object]) -> YaraReleaseIdentity:
    return YaraReleaseIdentity(
        release_id=dict.get(state, "release_id"),
        release_tag=dict.get(state, "release_tag"),
        package_kind=dict.get(state, "package_kind"),
        archive_asset_id=dict.get(state, "archive_asset_id"),
        archive_name=dict.get(state, "archive_name"),
        archive_url=dict.get(state, "archive_url"),
        manifest_asset_id=dict.get(state, "manifest_asset_id"),
        manifest_name=dict.get(state, "manifest_name"),
        manifest_url=dict.get(state, "manifest_url"),
    )


def _snapshot_with_expected(
    archive_path: Path,
    config: YaraConfig,
    identity: YaraReleaseIdentity,
    expected: str,
    manifest_sha256: str,
) -> YaraArchiveSnapshot:
    computed = file_sha256(archive_path, maximum_bytes=config.maximum_archive_bytes)
    if computed != expected:
        raise ValueError("yara_archive_manifest_mismatch")
    members = validate_rule_archive(archive_path, config)
    return YaraArchiveSnapshot(identity, archive_path, expected, computed, manifest_sha256, members)


def _snapshot_from_state(root: Path, config: YaraConfig, state: dict[str, object]) -> YaraArchiveSnapshot:
    identity = _identity_from_state(state)
    manifest_sha256 = sha256_text(dict.get(state, "manifest_sha256"), "yara_state_manifest_sha256_invalid")
    archive_path, manifest_path = official_artifact_paths(root, identity, manifest_sha256)
    if dict.get(state, "active_archive") != archive_path.name or dict.get(state, "active_manifest") != manifest_path.name:
        raise ValueError("yara_local_archive_path_state_invalid")
    if (
        path_contains_filesystem_alias(manifest_path)
        or not manifest_path.is_file()
        or manifest_path.stat().st_size > config.maximum_manifest_bytes
    ):
        raise ValueError("yara_local_manifest_unavailable")
    manifest_data = manifest_path.read_bytes()
    if bytes_sha256(manifest_data) != manifest_sha256:
        raise ValueError("yara_local_manifest_digest_mismatch")
    manifest = parse_release_manifest(manifest_data, maximum_bytes=config.maximum_manifest_bytes)
    return _snapshot_with_expected(
        archive_path,
        config,
        identity,
        manifest.expected_digest(identity.archive_name),
        manifest.manifest_sha256,
    )


def load_verified_official_archive(root: Path, config: YaraConfig, package: str) -> YaraArchiveAcquisition:
    if type(root) not in _PATH_TYPES or type(config) is not YaraConfig:
        raise TypeError("yara_local_archive_owner_invalid")
    require_real_directory(root)
    kind = package_kind(package)
    state = load_json_state(official_state_path(root, kind))
    if state is None or dict.get(state, "state_version") != _STATE_VERSION:
        raise ValueError("yara_local_archive_state_unavailable")
    snapshot = _snapshot_from_state(root, config, state)
    if snapshot.identity.package_kind != kind:
        raise ValueError("yara_local_archive_kind_mismatch")
    return YaraArchiveAcquisition(snapshot, "offline_active_cache", "local_revalidated", False)


def _conditional_headers(
    previous: dict[str, object] | None,
    identity: YaraReleaseIdentity,
    manifest_sha256: str,
    force_refresh: bool,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if (
        previous is None
        or dict.get(previous, "state_version") != _STATE_VERSION
        or dict.get(previous, "release_tag") != identity.release_tag
        or dict.get(previous, "manifest_sha256") != manifest_sha256
        or force_refresh
    ):
        return headers
    etag = dict.get(previous, "etag")
    modified = dict.get(previous, "last_modified")
    if type(etag) is str and etag:
        headers["If-None-Match"] = str.__str__(etag)
    if type(modified) is str and modified:
        headers["If-Modified-Since"] = str.__str__(modified)
    return headers


def _download_or_revalidate(
    root: Path,
    config: YaraConfig,
    identity: YaraReleaseIdentity,
    expected: str,
    manifest_sha256: str,
    *,
    timeout: int,
    opener: object | None,
    headers: dict[str, str],
) -> tuple[YaraArchiveSnapshot, str, str, str]:
    archive_path, _manifest_path = official_artifact_paths(root, identity, manifest_sha256)
    temp, etag, modified = download_archive_temp(
        identity.archive_url,
        root,
        identity.archive_name,
        maximum=config.maximum_archive_bytes,
        timeout=timeout,
        opener=opener,
        headers=headers,
    )
    if temp is None:
        try:
            snapshot = _snapshot_with_expected(archive_path, config, identity, expected, manifest_sha256)
        except (OSError, TypeError, ValueError, UnicodeError):
            temp, etag, modified = download_archive_temp(
                identity.archive_url,
                root,
                identity.archive_name,
                maximum=config.maximum_archive_bytes,
                timeout=timeout,
                opener=opener,
                headers={},
            )
            if temp is None:
                raise ValueError("yara_unconditional_archive_not_modified")
        else:
            return snapshot, "not_modified_revalidated", etag, modified
    try:
        snapshot = _snapshot_with_expected(temp, config, identity, expected, manifest_sha256)
        atomic_promote(temp, archive_path)
    finally:
        if temp.exists():
            temp.unlink()
    activated = YaraArchiveSnapshot(
        identity,
        archive_path,
        snapshot.expected_sha256,
        snapshot.computed_sha256,
        snapshot.manifest_sha256,
        snapshot.members,
    )
    return activated, "downloaded", etag, modified


def acquire_official_archive(
    root: Path,
    config: YaraConfig,
    package: str,
    *,
    force_refresh: bool = False,
    timeout: int = 45,
    opener: object | None = None,
) -> YaraArchiveAcquisition:
    if type(root) not in _PATH_TYPES or type(config) is not YaraConfig or type(force_refresh) is not bool:
        raise TypeError("yara_acquisition_owner_invalid")
    kind = package_kind(package)
    root.mkdir(parents=True, exist_ok=True)
    require_real_directory(root)
    previous = load_json_state(official_state_path(root, kind))
    try:
        release_data, _api_etag, _api_modified = request_bytes(
            config.release_api_url,
            maximum=4 * 1024 * 1024,
            timeout=timeout,
            opener=opener,
            release_asset=False,
        )
        identity = select_release_identity(release_data, kind)
        manifest_data, _manifest_etag, _manifest_modified = request_bytes(
            identity.manifest_url,
            maximum=config.maximum_manifest_bytes,
            timeout=timeout,
            opener=opener,
            release_asset=True,
        )
        manifest = parse_release_manifest(manifest_data, maximum_bytes=config.maximum_manifest_bytes)
        snapshot, freshness, etag, modified = _download_or_revalidate(
            root,
            config,
            identity,
            manifest.expected_digest(identity.archive_name),
            manifest.manifest_sha256,
            timeout=timeout,
            opener=opener,
            headers=_conditional_headers(previous, identity, manifest.manifest_sha256, force_refresh),
        )
        if freshness == "not_modified_revalidated" and previous is not None:
            previous_etag = dict.get(previous, "etag")
            previous_modified = dict.get(previous, "last_modified")
            etag = str.__str__(previous_etag) if type(previous_etag) is str else ""
            modified = str.__str__(previous_modified) if type(previous_modified) is str else ""
        archive_path, manifest_path = official_artifact_paths(root, identity, manifest.manifest_sha256)
        if archive_path != snapshot.local_path:
            raise ValueError("yara_archive_activation_path_invalid")
        atomic_bytes(manifest_path, manifest_data)
        atomic_json(official_state_path(root, kind), {
            "state_version": _STATE_VERSION,
            "release_id": identity.release_id,
            "release_tag": identity.release_tag,
            "package_kind": identity.package_kind,
            "archive_asset_id": identity.archive_asset_id,
            "archive_name": identity.archive_name,
            "archive_url": identity.archive_url,
            "manifest_asset_id": identity.manifest_asset_id,
            "manifest_name": identity.manifest_name,
            "manifest_url": identity.manifest_url,
            "archive_sha256": snapshot.computed_sha256,
            "expected_sha256": snapshot.expected_sha256,
            "manifest_sha256": snapshot.manifest_sha256,
            "active_archive": archive_path.name,
            "active_manifest": manifest_path.name,
            "etag": etag,
            "last_modified": modified,
        })
        return YaraArchiveAcquisition(snapshot, "github_release_api", freshness, True)
    except (OSError, TypeError, ValueError, UnicodeError, urllib.error.URLError):
        local = load_verified_official_archive(root, config, kind)
        return YaraArchiveAcquisition(
            local.snapshot,
            "offline_last_known_good_cache",
            "last_known_good_retained",
            False,
        )


__all__ = (
    "acquire_official_archive", "load_verified_official_archive",
    "official_artifact_paths", "official_state_path",
)
