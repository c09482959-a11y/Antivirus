"""Canonical POSIX symbolic-link and Windows reparse-point decisions."""
from __future__ import annotations

import os
from pathlib import Path, PosixPath, WindowsPath
import stat

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


def _exact_absolute_path(value: object) -> Path:
    if type(value) not in _PATH_TYPES:
        raise TypeError("filesystem_alias_path_invalid")
    return value if value.is_absolute() else value.absolute()


def windows_file_attributes_indicate_alias(attributes: object) -> bool:
    """Classify an exact Windows file-attribute value."""
    if type(attributes) is not int:
        raise TypeError("filesystem_alias_windows_attributes_invalid")
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def stat_result_is_filesystem_alias(state: object) -> bool:
    """Classify a native lstat result without following its entry."""
    if type(state) is not os.stat_result:
        raise TypeError("filesystem_alias_stat_result_invalid")
    return stat.S_ISLNK(state.st_mode) or windows_file_attributes_indicate_alias(
        int(getattr(state, "st_file_attributes", 0))
    )


def path_contains_filesystem_alias(path: object) -> bool:
    """Inspect every existing unresolved component of one exact path."""
    absolute = _exact_absolute_path(path)
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            state = current.lstat()
        except FileNotFoundError:
            return False
        if stat_result_is_filesystem_alias(state):
            return True
        if current != absolute and not stat.S_ISDIR(state.st_mode):
            return False
    return False


__all__ = (
    "path_contains_filesystem_alias",
    "stat_result_is_filesystem_alias",
    "windows_file_attributes_indicate_alias",
)
