"""Canonical defaulting no-hook text helper for scheduler queue modules."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def queue_default_text(value: object, default: str) -> str:
    """Return accepted text, otherwise a caller-supplied stable default."""
    text, reason = no_hook_text(
        value,
        missing_reason=default + "_missing",
        unsupported_reason=default + "_rejected",
    )
    return text if reason == "" and text != "" else default


__all__ = ("queue_default_text",)
