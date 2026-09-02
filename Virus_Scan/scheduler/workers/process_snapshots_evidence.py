"""Replayable decisions for process worker snapshot boundaries."""
from __future__ import annotations

from dataclasses import dataclass
from types import BuiltinFunctionType

from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE
from Virus_Scan.scheduler.internal.live_worker_entries import freeze_live_worker_entries

_OWNED_REPORTER_TYPES = (RUNTIME_NATIVE_FUNCTION_TYPE, BuiltinFunctionType)
_EMPTY_WORKER_ENTRIES: tuple[tuple[object, object, object, tuple[object, ...]], ...] = ()
_EMPTY_SUPPRESSED_FAILURES: tuple[str, ...] = ()
_NO_SUPPRESSED_FAILURE_ISSUE = str()
_REPORTER_REJECTED_ISSUE = "monitor_loop_suppressed_report_rejected"
_REPORTER_FAILED_ISSUE = "monitor_loop_suppressed_report_failed"
_SUPPRESSED_FAILURES_REJECTED_ISSUE = "process_worker_snapshot_suppressed_failures_rejected"
_SUPPRESSED_FAILURE_REJECTED_ISSUE = "process_worker_snapshot_suppressed_failure_rejected"


@dataclass(frozen=True)
class ProcessWorkerEntriesDecision:
    """Replayable decision for worker process-entry materialization."""

    entries: tuple[tuple[object, object, object, tuple[object, ...]], ...]
    reason: str
    accepted: bool
    missing: bool = False


@dataclass(frozen=True)
class ProcessSuppressedFailuresDecision:
    """Replayable decision for suppressed-failure tuple materialization."""

    entries: tuple[str, ...]
    reason: str
    accepted: bool
    missing: bool = False


@dataclass(frozen=True)
class ProcessSuppressedFailureReportDecision:
    """Replayable decision for suppressed-failure reporter execution."""

    issue: str
    reason: str
    reported: bool
    accepted: bool


def process_worker_entries_decision(value: object) -> ProcessWorkerEntriesDecision:
    if value is None:
        return ProcessWorkerEntriesDecision(
            entries=_EMPTY_WORKER_ENTRIES,
            reason="process_worker_entries_missing",
            accepted=False,
            missing=True,
        )
    return ProcessWorkerEntriesDecision(
        entries=freeze_live_worker_entries(value),
        reason="process_worker_entries_materialized",
        accepted=True,
    )


def process_suppressed_failures_decision(value: object) -> ProcessSuppressedFailuresDecision:
    if value is None:
        return ProcessSuppressedFailuresDecision(
            entries=_EMPTY_SUPPRESSED_FAILURES,
            reason="process_worker_snapshot_suppressed_failures_missing",
            accepted=False,
            missing=True,
        )
    if type(value) not in {list, tuple}:
        return ProcessSuppressedFailuresDecision(
            entries=(_SUPPRESSED_FAILURES_REJECTED_ISSUE,),
            reason="process_worker_snapshot_suppressed_failures_rejected",
            accepted=False,
        )
    failures: list[str] = []
    for item in value:
        if type(item) is str:
            failures.append(str.__str__(item))
        else:
            failures.append(_SUPPRESSED_FAILURE_REJECTED_ISSUE)
    return ProcessSuppressedFailuresDecision(
        entries=tuple(failures),
        reason="process_worker_snapshot_suppressed_failures_materialized",
        accepted=True,
    )


def process_suppressed_failure_report_decision(
    report_suppressed: object,
    label: str,
    exc: BaseException,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> ProcessSuppressedFailureReportDecision:
    if type(report_suppressed) not in _OWNED_REPORTER_TYPES:
        return ProcessSuppressedFailureReportDecision(
            issue=_REPORTER_REJECTED_ISSUE,
            reason="monitor_loop_suppressed_report_rejected",
            reported=False,
            accepted=False,
        )
    try:
        report_suppressed(label, exc)
    except recoverable_exceptions:
        return ProcessSuppressedFailureReportDecision(
            issue=_REPORTER_FAILED_ISSUE,
            reason="monitor_loop_suppressed_report_failed",
            reported=False,
            accepted=True,
        )
    return ProcessSuppressedFailureReportDecision(
        issue=_NO_SUPPRESSED_FAILURE_ISSUE,
        reason="monitor_loop_suppressed_report_recorded",
        reported=True,
        accepted=True,
    )


__all__ = (
    "ProcessSuppressedFailureReportDecision",
    "ProcessSuppressedFailuresDecision",
    "ProcessWorkerEntriesDecision",
    "process_suppressed_failure_report_decision",
    "process_suppressed_failures_decision",
    "process_worker_entries_decision",
)
