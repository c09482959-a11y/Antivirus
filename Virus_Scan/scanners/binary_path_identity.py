"""Scanner-owned no-hook path identity helpers for binary/filetype analysis."""
from __future__ import annotations

from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def _is_exact_stdlib_path(path: object) -> bool:
    return type(path) in (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)


def binary_path_text_with_reason(path: object) -> tuple[str, str]:
    """Return scanner path text plus explicit rejection reason without hooks."""
    if path is None:
        return "", "missing_binary_scan_path"
    if _is_exact_stdlib_path(path):
        return PurePath.as_posix(path), ""
    text, reason = no_hook_text(
        path,
        missing_reason="missing_binary_scan_path",
        unsupported_reason="unsafe_binary_scan_path_rejected",
    )
    if reason:
        return "", reason
    return text, ""


def binary_path_text(path: object) -> str:
    """Return scanner path text without caller-owned path/string hooks."""
    text, _reason = binary_path_text_with_reason(path)
    return text


def get_binary_scan_extension_with_reason(path: object) -> tuple[str, str]:
    """Return normalized extension plus explicit rejection reason."""
    text, reason = binary_path_text_with_reason(path)
    name = Path(text).name.lower().strip()
    if name in {"global-metadata.dat", "metadata.dat"}:
        return name, reason
    return Path(name).suffix.lower(), reason


def get_binary_scan_extension(path: object) -> str:
    """Return a normalized scanner-owned extension token for binary decisions."""
    ext, _reason = get_binary_scan_extension_with_reason(path)
    return ext


def normalize_binary_profile_extension(path: object) -> str:
    ext = get_binary_scan_extension(path)
    return ext or "<no_ext>"


__all__ = (
    "binary_path_text",
    "binary_path_text_with_reason",
    "get_binary_scan_extension",
    "get_binary_scan_extension_with_reason",
    "normalize_binary_profile_extension",
)
