"""Deadline-indexed job evaluation for the in-memory timeout owner."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.timeout.inmemory_timeout_deadline_policy import next_timeout_check_deadline
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_contracts import TimeoutSweepJobCounters as _TimeoutSweepJobCounters
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import record_timeout_recovery_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_job_steps import (
    evaluate_assigned_timeout_job_state,
    evaluate_queued_timeout_job_state,
    evaluate_running_timeout_job_state,
)
if TYPE_CHECKING:
    from Virus_Scan.scheduler.timeout import inmemory_timeout_sweep_contracts as sweep_types

def _record_malformed_job_record(
    *,
    timeout_retry_evidence: list[sweep_types.SweepEvidenceRecord],
    jid: object,
    rec: object,
    record_scheduler_suppressed: sweep_types.TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    record_timeout_recovery_failure(
        failures=timeout_retry_evidence,
        job_id=jid,
        reason="job_record_malformed",
        pid=None,
        action="timeout_job_record_malformed",
        attempt=0,
        timeout_budget={},
        error=TypeError("job record must be an exact dict, got " + no_hook_type_name(rec)),
        source="inmemory_timeout_sweep.job_records",
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )


def _evaluate_timeout_job_state(
    *,
    counters: _TimeoutSweepJobCounters,
    jid: object,
    rec: sweep_types.TimeoutRecord,
    now: float,
    recovery: sweep_types.SweepRecovery,
    queued_unstarted_count: int,
    max_queued_unstarted: int,
    queued_start_timeout_sec: float,
    assigned_start_timeout_sec: float,
    heartbeat_stale_sec: float,
    progress_stale_sec: float,
    base_pf_timeout: float,
    cancel_grace_sec: float,
    start_wait_budget: sweep_types.TimeoutStartWaitBudget,
    stage_is_pre_execution: sweep_types.StagePredicate,
    update_ewma: sweep_types.SweepCallback,
    ewma_state: sweep_types.EwmaState,
    timeout_retry_evidence: list[sweep_types.SweepEvidenceRecord],
    timeout_reporting_failures: list[sweep_types.SweepEvidenceRecord],
    record_scheduler_suppressed: sweep_types.TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    state = dict.__getitem__(rec, "state") if dict.__contains__(rec, "state") else None
    if state == "queued":
        evaluate_queued_timeout_job_state(
            counters=counters,
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
    elif state == "assigned":
        evaluate_assigned_timeout_job_state(
            counters=counters,
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
    elif state == "running":
        evaluate_running_timeout_job_state(
            counters=counters,
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


def evaluate_timeout_sweep_jobs(
    *,
    due_job_ids: tuple[int, ...],
    state_index: object,
    job_records: sweep_types.SweepJobRecords,
    terminal: sweep_types.SchedulerTerminalSet,
    now: float,
    recovery: sweep_types.SweepRecovery,
    max_queued_unstarted: int,
    queued_start_timeout_sec: float,
    assigned_start_timeout_sec: float,
    heartbeat_stale_sec: float,
    progress_stale_sec: float,
    base_pf_timeout: float,
    cancel_grace_sec: float,
    start_wait_budget: sweep_types.TimeoutStartWaitBudget,
    stage_is_pre_execution: sweep_types.StagePredicate,
    update_ewma: sweep_types.SweepCallback,
    ewma_state: sweep_types.EwmaState,
    timeout_retry_evidence: list[sweep_types.SweepEvidenceRecord],
    timeout_reporting_failures: list[sweep_types.SweepEvidenceRecord],
    record_scheduler_suppressed: sweep_types.TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> _TimeoutSweepJobCounters:
    """Evaluate only jobs emitted by the canonical deadline index."""
    counters = _TimeoutSweepJobCounters()
    if type(job_records) is not dict:
        return counters
    queued_unstarted_count = state_index.queued_unstarted_count()
    for jid in due_job_ids:
        if type(terminal) is set and set.__contains__(terminal, jid):
            state_index.sync_record(jid, None, due_at=None)
            continue
        rec = dict.get(job_records, jid)
        counters.evaluated += 1
        if type(rec) is not dict:
            _record_malformed_job_record(
                timeout_retry_evidence=timeout_retry_evidence,
                jid=jid,
                rec=rec,
                record_scheduler_suppressed=record_scheduler_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            )
            state_index.sync_record(jid, rec, due_at=None)
            continue
        _evaluate_timeout_job_state(
            counters=counters,
            jid=jid,
            rec=rec,
            now=now,
            recovery=recovery,
            queued_unstarted_count=queued_unstarted_count,
            max_queued_unstarted=max_queued_unstarted,
            queued_start_timeout_sec=queued_start_timeout_sec,
            assigned_start_timeout_sec=assigned_start_timeout_sec,
            heartbeat_stale_sec=heartbeat_stale_sec,
            progress_stale_sec=progress_stale_sec,
            base_pf_timeout=base_pf_timeout,
            cancel_grace_sec=cancel_grace_sec,
            start_wait_budget=start_wait_budget,
            stage_is_pre_execution=stage_is_pre_execution,
            update_ewma=update_ewma,
            ewma_state=ewma_state,
            timeout_retry_evidence=timeout_retry_evidence,
            timeout_reporting_failures=timeout_reporting_failures,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        current = dict.get(job_records, jid)
        deadline = next_timeout_check_deadline(
            record=current,
            now=now,
            queued_start_timeout_sec=queued_start_timeout_sec,
            assigned_start_timeout_sec=assigned_start_timeout_sec,
            heartbeat_stale_sec=heartbeat_stale_sec,
            progress_stale_sec=progress_stale_sec,
            base_pf_timeout=base_pf_timeout,
            cancel_grace_sec=cancel_grace_sec,
            start_wait_budget=start_wait_budget,
        )
        state_index.sync_record(jid, current, due_at=deadline)
    return counters


__all__ = ("evaluate_timeout_sweep_jobs",)
