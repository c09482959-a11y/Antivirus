"""Archive-owned path containment helpers for member extraction."""
from __future__ import annotations

import os
from pathlib import Path

from Virus_Scan.scanners.archives.text_boundaries import archive_type_diagnostic
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS

_EXACT_PATH_TYPE = type(Path("."))


def _archive_root_path(root: object) -> tuple[Path | None, str]:
    """Return an owned archive root path without invoking caller-owned hooks."""
    if type(root) is str:
        root_text = str.__str__(root)
        if not str.strip(root_text):
            return None, "archive_root_missing"
        try:
            return Path(root_text).resolve(), ""
        except IO_CONFIGURATION_ERRORS:
            return None, "archive_root_resolution_failed"
    if type(root) is _EXACT_PATH_TYPE:
        try:
            return root.resolve(), ""
        except IO_CONFIGURATION_ERRORS:
            return None, "archive_root_resolution_failed"
    return None, archive_type_diagnostic("unsafe_archive_root_rejected:", root)


def _archive_member_name(member_name: object) -> tuple[str, str]:
    """Return exact archive member text without bool/str/fspath hooks."""
    if type(member_name) is str:
        name = str.__str__(member_name)
        if not name:
            return "", "archive_member_name_missing"
        return name, ""
    if member_name is None:
        return "", "archive_member_name_missing"
    return "", archive_type_diagnostic("unsafe_archive_member_name_rejected:", member_name)


def safe_archive_child_path_with_reason(root: str | os.PathLike[str], member_name: str) -> tuple[Path | None, str]:
    """Return a normalized child path plus an explicit rejection reason.

    The boundary accepts exact built-in strings and the exact platform pathlib
    path type used by the scanner's own temporary directory tests. Unknown
    path-like or string-like objects are rejected before ``__fspath__``,
    ``__bool__``, ``__str__``, descriptors, or iterable hooks can execute.
    """
    root_path, root_reason = _archive_root_path(root)
    if root_reason:
        return None, root_reason
    name, name_reason = _archive_member_name(member_name)
    if name_reason:
        return None, name_reason
    if root_path is None:
        return None, "archive_root_resolution_failed"
    if os.path.isabs(name):
        return None, "archive_member_absolute_path_rejected"
    try:
        candidate = (root_path / name).resolve()
    except IO_CONFIGURATION_ERRORS:
        return None, "archive_member_path_resolution_failed"
    if root_path == candidate or root_path in candidate.parents:
        return candidate, ""
    return None, "archive_member_path_escape_rejected"


def safe_archive_child_path(root: str | os.PathLike[str], member_name: str) -> Path | None:
    """Return a normalized archive member target only when it stays under root."""
    path, reason = safe_archive_child_path_with_reason(root, member_name)
    if reason:
        return None
    return path


__all__ = ("safe_archive_child_path", "safe_archive_child_path_with_reason")
