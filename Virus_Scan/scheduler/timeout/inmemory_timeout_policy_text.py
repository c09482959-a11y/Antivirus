"""Canonical timeout policy text and reason helpers."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text


def timeout_policy_field_text(field: object) -> str:
    """Return the no-hook text form for timeout policy field names."""
    return scheduler_evidence_text(
        field,
        missing_text="timeout_policy_field",
        field_name="timeout_policy_field",
    )


def timeout_policy_reason(field: object, suffix: str) -> str:
    """Return the canonical timeout policy reason for a field and suffix."""
    return timeout_policy_field_text(field) + "_" + suffix


__all__ = ("timeout_policy_field_text", "timeout_policy_reason")
