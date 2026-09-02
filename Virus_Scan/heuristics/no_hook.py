"""No-hook text helpers for heuristic scanners."""
from __future__ import annotations

from pathlib import Path, PosixPath, WindowsPath
from Virus_Scan.contracts.no_hook_materialization import no_hook_text

_OWNED_PATH_TYPES = (Path, PosixPath, WindowsPath)


def heuristic_text(value: object, default: str = "") -> str:
    if type(value) is bytes:
        return bytes(value).decode("latin1", errors="ignore")
    if type(value) is bytearray:
        return bytes(value).decode("latin1", errors="ignore")
    text, reason = no_hook_text(
        value,
        missing_reason="missing_heuristic_text",
        unsupported_reason="unsafe_heuristic_text_rejected",
    )
    if not reason:
        return text
    if type(value) in _OWNED_PATH_TYPES:
        try:
            return str(value)
        except (OSError, TypeError, ValueError, RuntimeError):
            return default
    return default


def heuristic_lower(value: object, default: str = "") -> str:
    text = heuristic_text(value, default)
    return str.lower(text) if text else default


__all__ = ("heuristic_lower", "heuristic_text")
