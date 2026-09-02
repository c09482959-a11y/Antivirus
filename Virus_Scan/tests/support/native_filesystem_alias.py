"""Native filesystem-alias fixtures for the frozen Linux/Windows platforms."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
import subprocess

from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.runtime.api import (
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
)

_PATH_TYPES = (Path, PosixPath, WindowsPath)


@dataclass(frozen=True, slots=True)
class NativeFilesystemAlias:
    path: Path
    entry: Path
    target: Path
    kind: str

    def __post_init__(self) -> None:
        if type(self) is not NativeFilesystemAlias:
            raise TypeError("native_filesystem_alias_owner_invalid")
        if any(type(value) not in _PATH_TYPES for value in (self.path, self.entry, self.target)):
            raise TypeError("native_filesystem_alias_path_invalid")
        if self.kind not in ("posix_symlink", "windows_directory_junction"):
            raise ValueError("native_filesystem_alias_kind_invalid")


def _create_directory_entry(entry: Path, target: Path) -> str:
    platform = runtime_platform_identity().operating_system
    if platform == "linux":
        entry.symlink_to(target, target_is_directory=True)
        kind = "posix_symlink"
    elif platform == "windows":
        completed = subprocess.run(
            ("cmd.exe", "/d", "/c", "mklink", "/J", str(entry), str(target)),
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise AssertionError(
                "native_windows_directory_junction_creation_failed:"
                + completed.stderr.strip()
            )
        kind = "windows_directory_junction"
    else:
        raise AssertionError("native_filesystem_alias_platform_unsupported")
    if not path_contains_filesystem_alias(entry):
        raise AssertionError("native_filesystem_alias_not_classified")
    if not stat_result_is_filesystem_alias(entry.lstat()):
        raise AssertionError("native_filesystem_alias_entry_not_classified")
    return kind


def create_native_directory_alias(entry: Path, target: Path) -> NativeFilesystemAlias:
    if type(entry) not in _PATH_TYPES or type(target) not in _PATH_TYPES:
        raise TypeError("native_filesystem_alias_path_invalid")
    if entry.exists() or entry.is_symlink() or not target.is_dir():
        raise ValueError("native_filesystem_directory_alias_precondition_invalid")
    entry.parent.mkdir(parents=True, exist_ok=True)
    kind = _create_directory_entry(entry, target)
    return NativeFilesystemAlias(entry, entry, target, kind)


def create_native_file_alias(entry: Path, target: Path) -> NativeFilesystemAlias:
    if type(entry) not in _PATH_TYPES or type(target) not in _PATH_TYPES:
        raise TypeError("native_filesystem_alias_path_invalid")
    if entry.exists() or entry.is_symlink() or not target.is_file():
        raise ValueError("native_filesystem_file_alias_precondition_invalid")
    entry.parent.mkdir(parents=True, exist_ok=True)
    platform = runtime_platform_identity().operating_system
    if platform == "linux":
        entry.symlink_to(target)
        if not path_contains_filesystem_alias(entry) or not stat_result_is_filesystem_alias(entry.lstat()):
            raise AssertionError("native_filesystem_alias_not_classified")
        return NativeFilesystemAlias(entry, entry, target, "posix_symlink")
    if platform != "windows":
        raise AssertionError("native_filesystem_alias_platform_unsupported")
    alias_parent = entry.with_name(entry.name + ".junction")
    kind = _create_directory_entry(alias_parent, target.parent)
    alias_path = alias_parent / target.name
    if not alias_path.is_file() or not path_contains_filesystem_alias(alias_path):
        raise AssertionError("native_filesystem_file_alias_not_classified")
    return NativeFilesystemAlias(alias_path, alias_parent, target, kind)


__all__ = (
    "NativeFilesystemAlias",
    "create_native_directory_alias",
    "create_native_file_alias",
)
