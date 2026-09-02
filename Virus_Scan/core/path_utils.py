"""Pure path helpers split away from the broad core.paths module."""
from __future__ import annotations

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
import os


_STDLIB_PATH_TYPES = (
    Path,
    PosixPath,
    WindowsPath,
    PurePosixPath,
    PureWindowsPath,
)


def _path_reason(field_name: str, suffix: str) -> str:
    if type(field_name) is str and field_name:
        return str.__add__(str.__str__(field_name), suffix)
    return str.__add__("path", suffix)


def core_path_text(value: object, *, field_name: str = "path", allow_empty: bool = False) -> tuple[str, str]:
    """Return path text without invoking caller-owned conversion hooks."""
    if isinstance(value, str):
        text = str.__str__(value)
    elif type(value) in _STDLIB_PATH_TYPES:
        text = PurePath.as_posix(value)
    else:
        return "", _path_reason(field_name, "_rejected")
    if not allow_empty and text == "":
        return "", _path_reason(field_name, "_missing")
    return text, ""


def safe_child_path(root: str | os.PathLike[str], member_name: str) -> Path | None:
    """Return a normalized child path if it stays under *root*, else None."""
    root_text, root_reason = core_path_text(root, field_name="child_root")
    name, name_reason = core_path_text(member_name, field_name="child_member")
    if root_reason or name_reason or os.path.isabs(name):
        return None
    try:
        root_path = Path(root_text).resolve()
        candidate = (root_path / name).resolve()
        if root_path == candidate or root_path in candidate.parents:
            return candidate
    except IO_CONFIGURATION_ERRORS:
        candidate = None
    return None


def ensure_parent_dir(path: str | os.PathLike[str]) -> Path:
    text, reason = core_path_text(path, field_name="parent_path")
    if reason:
        raise ValueError(reason)
    p = Path(text)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p
