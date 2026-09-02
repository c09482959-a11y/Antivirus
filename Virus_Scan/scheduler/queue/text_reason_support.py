"""Canonical no-hook text + empty-reason materialization for queue policy surfaces."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def queue_text_or_empty_reason(
    value: object,
    *,
    missing_reason: str,
    unsupported_reason: str,
    empty_reason: str,
) -> tuple[str, str]:
    """Return exact text plus explicit unavailable/empty reason evidence."""
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    if reason:
        return reason, reason
    if text:
        return text, ""
    return empty_reason, empty_reason


__all__ = ("queue_text_or_empty_reason",)
