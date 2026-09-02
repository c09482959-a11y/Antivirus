"""Canonical no-hook pickle literal text materialization."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def pickle_literal_text(value: object, *, default: object = '') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_pickle_literal_text",
        unsupported_reason="unsafe_pickle_literal_text_rejected",
    )
    return default if reason else text


__all__ = ("pickle_literal_text",)
