"""Replayable scheduler status support decisions for final JSON projection."""
from __future__ import annotations

from dataclasses import dataclass



@dataclass(frozen=True, slots=True)
class EmptySchedulerStatusDecision:
    """Decision for classifying an empty scheduler status carrier."""

    is_empty: bool
    reason: str
    value_type: str


def empty_scheduler_status_decision(value: object) -> EmptySchedulerStatusDecision:
    if value is None:
        return EmptySchedulerStatusDecision(
            is_empty=True,
            reason="scheduler_status_missing",
            value_type="NoneType",
        )
    if type(value) is str and value == "":
        return EmptySchedulerStatusDecision(
            is_empty=True,
            reason="scheduler_status_blank_text",
            value_type="str",
        )
    if type(value) in {dict, list, tuple, set, frozenset} and len(value) == 0:
        return EmptySchedulerStatusDecision(
            is_empty=True,
            reason="scheduler_status_empty_container",
            value_type=type(value).__name__,
        )
    return EmptySchedulerStatusDecision(
        is_empty=False,
        reason="scheduler_status_available",
        value_type=type(value).__name__,
    )


__all__ = ("EmptySchedulerStatusDecision", "empty_scheduler_status_decision")
