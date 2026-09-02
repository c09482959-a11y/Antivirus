"""Progress-stall timeout decisions for running in-memory workers."""
from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_contracts import RunningProgressStallRequest
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_progress_cancel import evaluate_progress_stall_cancellation
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_progress_preexecution import handle_pre_execution_progress_wait


def evaluate_running_progress_stall(request: RunningProgressStallRequest) -> tuple[int, int]:
    """Return progress-stall and cancelled-after-stall deltas."""

    if handle_pre_execution_progress_wait(
        jid=request.jid,
        rec=request.rec,
        now=request.now,
        pid=request.pid,
        budget_info=request.budget_info,
        recovery=request.recovery,
        stage_is_pre_execution=request.stage_is_pre_execution,
        timeout_retry_evidence=request.timeout_retry_evidence,
        record_scheduler_suppressed=request.record_scheduler_suppressed,
        recoverable_exceptions=request.recoverable_exceptions,
    ):
        return 1, 0
    return evaluate_progress_stall_cancellation(
        jid=request.jid,
        rec=request.rec,
        now=request.now,
        pid=request.pid,
        progress_age=request.progress_age,
        budget_info=request.budget_info,
        recovery=request.recovery,
        cancel_grace_sec=request.cancel_grace_sec,
        update_ewma=request.update_ewma,
        ewma_state=request.ewma_state,
        timeout_retry_evidence=request.timeout_retry_evidence,
        timeout_reporting_failures=request.timeout_reporting_failures,
        record_scheduler_suppressed=request.record_scheduler_suppressed,
        recoverable_exceptions=request.recoverable_exceptions,
    )


__all__ = ("evaluate_running_progress_stall",)
