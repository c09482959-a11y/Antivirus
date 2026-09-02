"""Canonical raw queue terminal finalization facade."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.queue.terminal_accounting_evidence import (
    report_terminal_accounting_failure,
    terminal_terminating_message,
    terminal_waiting_message,
)
from Virus_Scan.scheduler.queue.terminal_accounting_support import (
    accounting_float,
    accounting_int,
)
from Virus_Scan.scheduler.queue.terminal_worker_cleanup import terminate_processes


@dataclass(frozen=True, slots=True)
class IdleQueueFinalizationRequest:
    """Internal request for terminal accounting after queue idleness."""

    no_live_queue_work: bool
    accounted_files: int
    total_files: int
    idle_elapsed: float
    idle_notice_sec: float
    idle_grace_sec: float
    live_workers: int
    procs: Iterable[tuple[object, object, object, object]]
    terminate_worker: Callable[..., object]
    report: Callable[..., object]
    log_info: Callable[[str], object]
    sleep: Callable[[float], object]


def idle_queue_finalization_decision(
    request: IdleQueueFinalizationRequest,
) -> tuple[bool, float]:
    """Apply terminal accounting through the canonical immutable request."""
    no_live, live_reason = scheduler_bool(
        request.no_live_queue_work,
        default=False,
        reason="queue_terminal_no_live_work_rejected",
    )
    accounted, accounted_ok = accounting_int(
        request.accounted_files, field_name="accounted_files", report=request.report
    )
    total, total_ok = accounting_int(
        request.total_files, field_name="total_files", report=request.report
    )
    elapsed, elapsed_ok = accounting_float(
        request.idle_elapsed, field_name="idle_elapsed", report=request.report
    )
    notice, notice_ok = accounting_float(
        request.idle_notice_sec, field_name="idle_notice_sec", report=request.report
    )
    grace, grace_ok = accounting_float(
        request.idle_grace_sec, field_name="idle_grace_sec", report=request.report
    )
    workers, workers_ok = accounting_int(
        request.live_workers, field_name="live_workers", report=request.report
    )
    if live_reason:
        report_terminal_accounting_failure(
            request.report,
            "queue_terminal_accounting_input_rejected",
            ValueError(live_reason),
        )
        return False, notice
    if not (
        accounted_ok
        and total_ok
        and elapsed_ok
        and notice_ok
        and grace_ok
        and workers_ok
    ):
        return False, notice
    if not (no_live and accounted >= total) or elapsed < notice:
        return False, notice
    request.log_info(terminal_waiting_message(workers))
    if elapsed >= grace:
        request.log_info(terminal_terminating_message(workers, grace))
        terminate_processes(
            request.procs,
            actions=("terminate", "kill"),
            terminate_worker=request.terminate_worker,
            report=request.report,
            sleep=request.sleep,
            context="queue_idle_finalization",
        )
        return True, notice
    return False, min(max(notice * 2.0, 2.0), 30.0)




__all__ = (
    'IdleQueueFinalizationRequest',
    'idle_queue_finalization_decision',
    'terminate_processes',
)
