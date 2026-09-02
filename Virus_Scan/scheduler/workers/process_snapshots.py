"""Worker-owned active process snapshots."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_int
from Virus_Scan.scheduler.workers.process_control_no_hook import call_process_method, safe_process_control_exception_name
from Virus_Scan.scheduler.workers.process_snapshots_evidence import (
    process_suppressed_failure_report_decision,
    process_suppressed_failures_decision,
    process_worker_entries_decision,
)



@dataclass(frozen=True)
class ProcessQueueWorkerSnapshot:
    """Immutable live-worker snapshot for process-queue monitoring."""

    live_count: int
    active_processes: tuple[tuple[object, object, object, tuple[object, ...]], ...]
    suppressed_failures: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        live_count, live_issue = worker_int(
            self.live_count,
            replacement=0,
            reason="process_worker_snapshot_live_count_rejected",
            minimum=0,
        )
        suppressed = list(
            process_suppressed_failures_decision(self.suppressed_failures).entries
        )
        if live_issue:
            suppressed.append(live_issue)
        object.__setattr__(self, "live_count", live_count)
        object.__setattr__(
            self,
            "active_processes",
            process_worker_entries_decision(self.active_processes).entries,
        )
        object.__setattr__(self, "suppressed_failures", tuple(suppressed))

    def as_tuple(self) -> tuple[int, tuple[tuple[object, object, object, tuple[object, ...]], ...]]:
        return self.live_count, self.active_processes


ProcessQueueWorkerEntry = tuple[object, object, object, tuple[object, ...]]


def _safe_process_snapshot_recoverable(recoverable_exceptions: object) -> tuple[type[BaseException], ...]:
    if type(recoverable_exceptions) is not tuple:
        return RECOVERABLE_RUNTIME_ERRORS
    return (
        tuple(
            exception_type
            for exception_type in recoverable_exceptions
            if type(exception_type) is type and issubclass(exception_type, BaseException)
        )
        or RECOVERABLE_RUNTIME_ERRORS
    )


def _snapshot_process_worker_entry(
    entry: ProcessQueueWorkerEntry,
    *,
    report_suppressed: object,
    safe_recoverable: tuple[type[BaseException], ...],
) -> tuple[ProcessQueueWorkerEntry | None, tuple[str, ...]]:
    idx, proc, output, cmd = entry
    suppressed: list[str] = []
    try:
        poll_result, poll_issue = call_process_method(proc, "poll")
        if poll_issue:
            suppressed.append(poll_issue)
            report_issue = process_suppressed_failure_report_decision(
                report_suppressed,
                "monitor_loop_suppressed",
                RuntimeError(poll_issue),
                safe_recoverable,
            ).issue
            if report_issue:
                suppressed.append(report_issue)
            return None, tuple(suppressed)
        if poll_result is None:
            return (idx, proc, output, cmd), tuple(suppressed)
    except safe_recoverable as suppressed_exc:
        label = "monitor_loop_suppressed"
        suppressed.append(label)
        suppressed.append(safe_process_control_exception_name(suppressed_exc))
        report_issue = process_suppressed_failure_report_decision(
            report_suppressed,
            label,
            suppressed_exc,
            safe_recoverable,
        ).issue
        if report_issue:
            suppressed.append(report_issue)
    return None, tuple(suppressed)


def snapshot_active_process_queue_workers(procs: object, *, recoverable_exceptions: object, report_suppressed: object) -> ProcessQueueWorkerSnapshot:
    """Return immutable live-worker snapshot for process-queue monitoring."""
    safe_recoverable = _safe_process_snapshot_recoverable(recoverable_exceptions)
    snapshots = tuple(
        _snapshot_process_worker_entry(
            entry,
            report_suppressed=report_suppressed,
            safe_recoverable=safe_recoverable,
        )
        for entry in process_worker_entries_decision(procs).entries
    )
    active_procs = tuple(entry for entry, _issues in snapshots if entry is not None)
    suppressed = tuple(issue for _entry, issues in snapshots for issue in issues)
    return ProcessQueueWorkerSnapshot(len(active_procs), active_procs, suppressed)


__all__ = ("ProcessQueueWorkerSnapshot", "snapshot_active_process_queue_workers")
