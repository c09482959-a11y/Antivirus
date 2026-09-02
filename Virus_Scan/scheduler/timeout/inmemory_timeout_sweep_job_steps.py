"""Bounded timeout-sweep job-state evaluation helpers."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running import evaluate_running_timeout_state
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_waits import (
    evaluate_assigned_start_wait,
    evaluate_queued_start_wait,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.timeout import inmemory_timeout_sweep_contracts as sweep_types


def evaluate_queued_timeout_job_state(
    *,
    counters: object,
    jid: object,
    rec: sweep_types.TimeoutRecord,
    now: float,
    recovery: sweep_types.SweepRecovery,
    queued_unstarted_count: int,
    max_queued_unstarted: int,
    queued_start_timeout_sec: float,
    start_wait_budget: sweep_types.TimeoutStartWaitBudget,
    timeout_retry_evidence: list[sweep_types.SweepEvidenceRecord],
    record_scheduler_suppressed: sweep_types.TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Apply queued-start timeout accounting to one owned job record."""
    queued_wait_decision = evaluate_queued_start_wait(
        jid=jid,
        rec=rec,
        now=now,
        recovery=recovery,
        queued_unstarted_count=queued_unstarted_count,
        max_queued_unstarted=max_queued_unstarted,
        queued_start_timeout_sec=queued_start_timeout_sec,
        start_wait_budget=start_wait_budget,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    counters.queued_waits += queued_wait_decision.wait_delta


def evaluate_assigned_timeout_job_state(
    *,
    counters: object,
    jid: object,
    rec: sweep_types.TimeoutRecord,
    now: float,
    recovery: sweep_types.SweepRecovery,
    assigned_start_timeout_sec: float,
    start_wait_budget: sweep_types.TimeoutStartWaitBudget,
    timeout_retry_evidence: list[sweep_types.SweepEvidenceRecord],
    record_scheduler_suppressed: sweep_types.TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Apply assigned-start timeout accounting to one owned job record."""
    assigned_wait_decision = evaluate_assigned_start_wait(
        jid=jid,
        rec=rec,
        now=now,
        recovery=recovery,
        assigned_start_timeout_sec=assigned_start_timeout_sec,
        start_wait_budget=start_wait_budget,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    counters.assigned_waits += assigned_wait_decision.wait_delta


def evaluate_running_timeout_job_state(
    *,
    counters: object,
    jid: object,
    rec: sweep_types.TimeoutRecord,
    now: float,
    recovery: sweep_types.SweepRecovery,
    heartbeat_stale_sec: float,
    progress_stale_sec: float,
    base_pf_timeout: float,
    cancel_grace_sec: float,
    stage_is_pre_execution: sweep_types.StagePredicate,
    update_ewma: sweep_types.SweepCallback,
    ewma_state: sweep_types.EwmaState,
    timeout_retry_evidence: list[sweep_types.SweepEvidenceRecord],
    timeout_reporting_failures: list[sweep_types.SweepEvidenceRecord],
    record_scheduler_suppressed: sweep_types.TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Apply running-state timeout accounting to one owned job record."""
    hard_delta, orphan_delta, progress_delta, cancelled_delta = evaluate_running_timeout_state(
        jid=jid,
        rec=rec,
        now=now,
        recovery=recovery,
        heartbeat_stale_sec=heartbeat_stale_sec,
        progress_stale_sec=progress_stale_sec,
        base_pf_timeout=base_pf_timeout,
        cancel_grace_sec=cancel_grace_sec,
        stage_is_pre_execution=stage_is_pre_execution,
        update_ewma=update_ewma,
        ewma_state=ewma_state,
        timeout_retry_evidence=timeout_retry_evidence,
        timeout_reporting_failures=timeout_reporting_failures,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    counters.hard_timeouts += hard_delta
    counters.orphaned_workers += orphan_delta
    counters.progress_stalls += progress_delta
    counters.cancelled_after_stall += cancelled_delta


__all__ = (
    "evaluate_assigned_timeout_job_state",
    "evaluate_queued_timeout_job_state",
    "evaluate_running_timeout_job_state",
)
