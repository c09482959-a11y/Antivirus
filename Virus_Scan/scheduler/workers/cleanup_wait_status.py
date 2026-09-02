"""Shared bounded status and issue helpers for worker cleanup waits."""
from __future__ import annotations

from collections.abc import Callable

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.workers.cleanup_no_hook import call_cleanup_method
from Virus_Scan.scheduler.workers.process_control_no_hook import (
    safe_process_control_int,
)

_WorkerExitIssueReporter = Callable[..., object]


def wait_status(proc: object, timeout_value: float) -> int:
    status, wait_reason = call_cleanup_method(
        proc,
        "wait",
        timeout=timeout_value,
    )
    if wait_reason:
        raise RuntimeError(wait_reason)
    status_i, _status_reason = safe_process_control_int(
        status,
        replacement_value=-1,
        minimum=-1,
        reason="worker_cleanup_status_rejected",
    )
    return status_i


def record_worker_exit_issue(
    report_issue: _WorkerExitIssueReporter,
    failure_markers: list[str],
    marker: str,
    exc: BaseException,
    idx: int,
    output_s: str,
) -> None:
    try:
        report_issue(
            marker,
            exc,
            fatal=False,
            extra={"worker_idx": idx, "output": output_s},
        )
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS:
        failure_markers.append(marker + "_record_failed")


__all__ = ("record_worker_exit_issue", "wait_status")
