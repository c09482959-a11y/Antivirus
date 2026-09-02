"""Atomic generation of canonical root-level VirusTotal controls."""
from __future__ import annotations

import os
from pathlib import Path, PosixPath, WindowsPath
import stat
import tempfile

from Virus_Scan.runtime.api import (
    durable_replace_regular_file,
    flush_directory,
    flush_open_writable_file,
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
)

from Virus_Scan.virustotal.config import config_readme, config_schema_json, config_toml

_PATH_TYPES = (Path, PosixPath, WindowsPath)


def control_paths(root: Path) -> dict[str, Path]:
    if type(root) not in _PATH_TYPES:
        raise TypeError("virustotal_control_root_invalid")
    return {
        "config": root / "virustotal_config.toml",
        "defaults": root / "virustotal_defaults.toml",
        "schema": root / "virustotal_config.schema.json",
        "readme": root / "README.md",
    }


def _require_real_directory(path: Path) -> None:
    state = path.lstat()
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(state)
        or not stat.S_ISDIR(state.st_mode)
    ):
        raise ValueError("virustotal_control_root_invalid")


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
        raise ValueError("virustotal_control_path_invalid")
    return True


def _temporary_control(path: Path, content: str) -> Path:
    descriptor, raw_path = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(raw_path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
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
                raise ValueError("virustotal_control_path_invalid")
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


def ensure_generated_controls(root: Path) -> dict[str, Path]:
    paths = control_paths(root)
    root.mkdir(parents=True, exist_ok=True)
    _require_real_directory(root)
    _write_missing(paths["config"], config_toml())
    _write_missing(paths["defaults"], config_toml())
    _write_missing(paths["schema"], config_schema_json())
    _write_missing(paths["readme"], config_readme())
    return paths


def prepare_package_controls(root: Path) -> dict[str, Path]:
    paths = ensure_generated_controls(root)
    _write_exact(paths["defaults"], config_toml())
    _write_exact(paths["schema"], config_schema_json())
    _write_exact(paths["readme"], config_readme())
    return paths


__all__ = ("control_paths", "ensure_generated_controls", "prepare_package_controls")
