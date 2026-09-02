"""No-hook routing path boundary helpers.

Routing receives public file/container values from scanner, scheduler, and model
callers.  These helpers are the canonical routing-owned conversion point for
path-like inputs and intentionally reject caller-owned truthiness, string,
formatting, iteration, and fspath hooks before any filesystem/path scoring code
runs.
"""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.utils.text_validation import text_boundary_value


def routing_path_text(value: object, *, missing_reason: str = "routing_path_missing", unsupported_reason: str = "unsafe_routing_path_rejected") -> tuple[str, str]:
    """Return exact routing path text without invoking caller-owned hooks."""
    if value is None:
        return "", missing_reason
    text = text_boundary_value(value, unsupported=None)
    if type(text) is str:
        if text == "":
            return "", missing_reason
        return str.__str__(text), ""
    return "", unsupported_reason


def routing_path(value: object, *, missing_reason: str = "routing_path_missing", unsupported_reason: str = "unsafe_routing_path_rejected") -> tuple[Path | None, str]:
    """Return a pathlib path only after no-hook text materialization succeeds."""
    text, reason = routing_path_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason:
        return None, reason
    try:
        return Path(text), ""
    except (*IO_CONFIGURATION_ERRORS, TypeError, ValueError):
        return None, "routing_path_invalid"


def routing_optional_path(value: object, *, unsupported_reason: str = "unsafe_routing_path_rejected") -> tuple[Path | None, str]:
    """Return ``(None, "")`` for omitted optional path and fail closed for unsafe inputs."""
    if value is None:
        return None, ""
    return routing_path(value, unsupported_reason=unsupported_reason)


__all__ = ("routing_optional_path", "routing_path", "routing_path_text")
