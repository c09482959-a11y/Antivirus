"""Replayable scheduler-result final JSON projection decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_flag, first_exact_text

_OK_STATUSES = ("", "ok", "clean", "success", "passed")


@dataclass(frozen=True, slots=True)
class RootSchedulerStatusDecision:
    """Decision for whether root scheduler status requires a synthetic evidence record."""

    should_record: bool
    status_text: str
    degraded: bool
    fatal: bool
    reason: str


def root_scheduler_status_decision(record: Mapping[str, object]) -> RootSchedulerStatusDecision:
    if not isinstance(record, Mapping):
        return RootSchedulerStatusDecision(
            should_record=False,
            status_text="",
            degraded=False,
            fatal=False,
            reason="root_record_not_mapping",
        )
    status_text = first_exact_text(record, "scheduler_status", "status", "state").lower()
    degraded = exact_flag(record, "degraded")
    fatal = exact_flag(record, "fatal", "scheduler_fatal", "fatal_scheduler_failure")
    if not status_text and not degraded and not fatal:
        return RootSchedulerStatusDecision(
            should_record=False,
            status_text=status_text,
            degraded=degraded,
            fatal=fatal,
            reason="root_status_absent",
        )
    if status_text in _OK_STATUSES and not degraded and not fatal:
        return RootSchedulerStatusDecision(
            should_record=False,
            status_text=status_text,
            degraded=degraded,
            fatal=fatal,
            reason="root_status_ok",
        )
    return RootSchedulerStatusDecision(
        should_record=True,
        status_text=status_text,
        degraded=degraded,
        fatal=fatal,
        reason="root_status_requires_record",
    )


__all__ = ("RootSchedulerStatusDecision", "root_scheduler_status_decision")
