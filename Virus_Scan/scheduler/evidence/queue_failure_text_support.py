"""Canonical no-hook text projection for scheduler queue-failure evidence."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def queue_failure_text_value(
    value: object,
    *,
    default: str,
    missing_reason: str,
    unsupported_reason: str,
) -> tuple[str, str]:
    """Return accepted text or a replayable default/rejection reason."""
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    if reason or text == "":
        return default, reason or missing_reason
    return text, ""


__all__ = ("queue_failure_text_value",)
