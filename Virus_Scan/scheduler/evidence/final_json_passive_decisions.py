"""Replayable decisions for passive final JSON scheduler fields."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScalarFailureCategoryDecision:
    """Typed passive-scalar classification decision."""

    category: str
    failure_present: bool
    unsupported: bool
    reason: str

    @classmethod
    def no_failure(cls, reason: str) -> "ScalarFailureCategoryDecision":
        return cls("", failure_present=False, unsupported=False, reason=reason)

    @classmethod
    def failure(cls, category: str, reason: str) -> "ScalarFailureCategoryDecision":
        return cls(category, failure_present=True, unsupported=False, reason=reason)

    @classmethod
    def unsupported_category(cls, category: str, reason: str) -> "ScalarFailureCategoryDecision":
        return cls(category, failure_present=False, unsupported=True, reason=reason)


@dataclass(frozen=True, slots=True)
class SchedulerStatusKeyDecision:
    """Typed decision for passive scheduler-status key routing."""

    accepted: bool
    reason: str


def scheduler_status_key_decision(
    key: str,
    *,
    domain_fragments: tuple[str, ...],
    status_fragments: tuple[str, ...],
    specific_projection_fields: tuple[str, ...],
) -> SchedulerStatusKeyDecision:
    """Classify whether a passive field belongs to scheduler-status backstop handling."""

    text = key.lower()
    if text in {"evidence", "scheduler_failure_evidence", "scheduler_evidence"}:
        return SchedulerStatusKeyDecision(accepted=False, reason="scheduler_status_evidence_field_rejected")
    if text == "scheduler":
        return SchedulerStatusKeyDecision(accepted=True, reason="scheduler_status_root_field")
    if text in specific_projection_fields:
        return SchedulerStatusKeyDecision(accepted=False, reason="scheduler_status_specific_projection_owner")
    if text == "suppressed_failures":
        return SchedulerStatusKeyDecision(accepted=True, reason="scheduler_status_suppressed_failures_field")
    accepted = any(domain in text for domain in domain_fragments) and any(
        fragment in text for fragment in status_fragments
    )
    return SchedulerStatusKeyDecision(
        accepted,
        "scheduler_status_domain_fragment_match" if accepted else "scheduler_status_no_domain_status_match",
    )


__all__ = (
    "ScalarFailureCategoryDecision",
    "SchedulerStatusKeyDecision",
    "scheduler_status_key_decision",
)
