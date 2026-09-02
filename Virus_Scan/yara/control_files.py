"""Atomic generation of canonical root-level YARA package controls."""
from __future__ import annotations

import json
import os
from pathlib import Path, PosixPath, WindowsPath
import stat
import tempfile

from Virus_Scan.yara.config import config_readme, config_schema_json, config_toml
from Virus_Scan.yara.integrity import file_sha256
from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_directory,
    flush_open_writable_file,
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
)

_PATH_TYPES = (Path, PosixPath, WindowsPath)
YARA_RESOURCE_MANIFEST_VERSION = "yara_resource_manifest_v1"
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
_PINNED_ARCHIVES = (
    (
        "core",
        "yara-forge-rules-core.zip",
        1_700_208,
        "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f",
    ),
    (
        "extended",
        "yara-forge-rules-extended.zip",
        3_518_775,
        "756bd295a87603d78f1c879ecb7d217c91c1bcb03461c34e604fa20a4a0acae5",
    ),
)


def control_paths(root: Path) -> dict[str, Path]:
    if type(root) not in _PATH_TYPES:
        raise TypeError("yara_control_root_invalid")
    return {
        "config": root / "yara_config.toml",
        "defaults": root / "yara_defaults.toml",
        "schema": root / "yara_config.schema.json",
        "readme": root / "README.md",
        "manifest": root / "yara_resource_manifest.json",
        "lock": root / ".umige-yara.lock",
    }


def _require_real_directory(path: Path) -> None:
    state = path.lstat()
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(state)
        or not stat.S_ISDIR(state.st_mode)
    ):
        raise ValueError("yara_control_root_invalid")


def _existing_regular(path: Path) -> bool:
    try:
        state = path.lstat()
    except FileNotFoundError:
        return False
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(state)
        or not stat.S_ISREG(state.st_mode)
    ):
        raise ValueError("yara_control_path_invalid")
    return True


def _temporary_control(path: Path, content: str) -> Path:
    fd, raw_path = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(raw_path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            flush_open_writable_file(stream.fileno())
    except (OSError, UnicodeError, ValueError):
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _write_missing(path: Path, content: str) -> None:
    if _existing_regular(path):
        return
    temporary = _temporary_control(path, content)
    try:
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if not _existing_regular(path):
                raise ValueError("yara_control_path_invalid")
        flush_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _write_exact(path: Path, content: str) -> None:
    expected = content.encode("utf-8")
    if _existing_regular(path) and path.read_bytes() == expected:
        return
    temporary = _temporary_control(path, content)
    try:
        durable_replace_regular_file(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def resource_manifest_json(root: Path) -> str:
    if type(root) not in _PATH_TYPES:
        raise TypeError("yara_resource_manifest_root_invalid")
    resources: list[dict[str, object]] = []
    for package_kind, filename, expected_size, expected_digest in _PINNED_ARCHIVES:
        archive = root / filename
        if not _existing_regular(archive):
            raise ValueError("yara_packaged_archive_missing:" + package_kind)
        actual_size = archive.stat().st_size
        if actual_size != expected_size:
            raise ValueError("yara_packaged_archive_size_mismatch:" + package_kind)
        actual_digest = file_sha256(archive, maximum_bytes=_MAX_ARCHIVE_BYTES)
        if actual_digest != expected_digest:
            raise ValueError("yara_packaged_archive_digest_mismatch:" + package_kind)
        resources.append({
            "filename": filename,
            "package_kind": package_kind,
            "release_identity": "repository_pinned_yara_forge_resource",
            "sha256": actual_digest,
            "size": actual_size,
            "source_project": "YARAHQ/yara-forge",
        })
    record = {
        "manifest_version": YARA_RESOURCE_MANIFEST_VERSION,
        "resources": resources,
    }
    return json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n"


def ensure_generated_controls(root: Path) -> dict[str, Path]:
    """Create missing controls while preserving the editable configuration."""
    paths = control_paths(root)
    root.mkdir(parents=True, exist_ok=True)
    _require_real_directory(root)
    _write_missing(paths["config"], config_toml())
    _write_missing(paths["defaults"], config_toml())
    _write_missing(paths["schema"], config_schema_json())
    _write_missing(paths["readme"], config_readme())
    if all((root / item[1]).is_file() for item in _PINNED_ARCHIVES):
        _write_missing(paths["manifest"], resource_manifest_json(root))
    return paths


def prepare_package_controls(root: Path) -> dict[str, Path]:
    """Publish exact immutable package projections and preserve user config."""
    paths = ensure_generated_controls(root)
    _write_exact(paths["defaults"], config_toml())
    _write_exact(paths["schema"], config_schema_json())
    _write_exact(paths["readme"], config_readme())
    _write_exact(paths["manifest"], resource_manifest_json(root))
    return paths


__all__ = (
    "YARA_RESOURCE_MANIFEST_VERSION",
    "control_paths",
    "ensure_generated_controls",
    "prepare_package_controls",
    "resource_manifest_json",
)
