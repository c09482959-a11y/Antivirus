"""Bounded execution steps for the in-memory timeout sweep."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.timeout import inmemory_timeout_sweep_contracts as sweep_types
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_jobs import evaluate_timeout_sweep_jobs
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_result import (
    InMemoryTimeoutSweepResult,
    build_inmemory_timeout_sweep_result,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_shared import ingest_timeout_sweep_shared_heartbeats
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_wall_time import build_timeout_sweep_wall_time_failure_result


@dataclass(frozen=True, slots=True)
class TimeoutSweepRuntimeState:
    """Runtime evidence collected before per-job timeout evaluation."""

    now: float | None
    shared_heartbeat_result: object
    timeout_retry_evidence: list[object]
    timeout_reporting_failures: list[object]
    failure_result: InMemoryTimeoutSweepResult | None = None


def collect_timeout_sweep_runtime_state(
    *,
    state_index: object,
    job_records: sweep_types.SweepJobRecords,
    active: sweep_types.SchedulerActiveRecords,
    terminal: sweep_types.SchedulerTerminalSet,
    worker_heartbeats: sweep_types.SchedulerWorkerTable,
    worker_metrics: sweep_types.SchedulerWorkerTable,
    heartbeat_table: object,
    heartbeat_flags: object,
    read_heartbeat: sweep_types.SweepCallback,
    cancel_job: sweep_types.SweepCallback,
    lifecycle_recorder: sweep_types.SweepCallback,
    heartbeat_ingester: sweep_types.SweepCallback,
    monotonic_ns: sweep_types.MonotonicClock,
    wall_time: sweep_types.WallClock,
    record_scheduler_suppressed: sweep_types.TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> TimeoutSweepRuntimeState:
    """Ingest shared heartbeat state and read the sweep wall clock."""
    timeout_retry_evidence: list[object] = []
    timeout_reporting_failures: list[object] = []
    shared_heartbeat_result = ingest_timeout_sweep_shared_heartbeats(
        sweep_types.SharedHeartbeatIngestionRequest(
            active_job_ids=state_index.active_job_ids(),
            job_records=job_records,
            active=active,
            terminal=terminal,
            worker_heartbeats=worker_heartbeats,
            worker_metrics=worker_metrics,
            heartbeat_table=heartbeat_table,
            heartbeat_flags=heartbeat_flags,
            read_heartbeat=read_heartbeat,
            cancel_job=cancel_job,
            lifecycle_recorder=lifecycle_recorder,
            heartbeat_ingester=heartbeat_ingester,
            monotonic_ns=monotonic_ns,
            wall_time=wall_time,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
            timeout_reporting_failures=timeout_reporting_failures,
        )
    )
    try:
        now = wall_time()
    except recoverable_exceptions as wall_time_exc:
        failure_result = build_timeout_sweep_wall_time_failure_result(
            sweep_types.TimeoutSweepWallTimeFailureRequest(
                error=wall_time_exc,
                shared_heartbeat_result=shared_heartbeat_result,
                timeout_retry_evidence=tuple(timeout_retry_evidence),
                timeout_reporting_failures=timeout_reporting_failures,
                record_scheduler_suppressed=record_scheduler_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            )
        )
        return TimeoutSweepRuntimeState(
            now=None,
            shared_heartbeat_result=shared_heartbeat_result,
            timeout_retry_evidence=timeout_retry_evidence,
            timeout_reporting_failures=timeout_reporting_failures,
            failure_result=failure_result,
        )
    return TimeoutSweepRuntimeState(
        now=now,
        shared_heartbeat_result=shared_heartbeat_result,
        timeout_retry_evidence=timeout_retry_evidence,
        timeout_reporting_failures=timeout_reporting_failures,
    )


def evaluate_timeout_sweep_runtime_state(
    *,
    runtime_state: TimeoutSweepRuntimeState,
    state_index: object,
    job_records: sweep_types.SweepJobRecords,
    terminal: sweep_types.SchedulerTerminalSet,
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
    record_scheduler_suppressed: sweep_types.TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> InMemoryTimeoutSweepResult:
    """Evaluate per-job timeout state and build immutable sweep output."""
    if runtime_state.failure_result is not None:
        return runtime_state.failure_result
    due_job_ids = state_index.pop_due(runtime_state.now)
    counters = evaluate_timeout_sweep_jobs(
        due_job_ids=due_job_ids,
        state_index=state_index,
        job_records=job_records,
        terminal=terminal,
        now=runtime_state.now,
        recovery=recovery,
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
        timeout_retry_evidence=runtime_state.timeout_retry_evidence,
        timeout_reporting_failures=runtime_state.timeout_reporting_failures,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return build_inmemory_timeout_sweep_result(
        evaluated=counters.evaluated,
        queued_waits=counters.queued_waits,
        assigned_waits=counters.assigned_waits,
        hard_timeouts=counters.hard_timeouts,
        orphaned_workers=counters.orphaned_workers,
        progress_stalls=counters.progress_stalls,
        cancelled_after_stall=counters.cancelled_after_stall,
        shared_heartbeat_result=runtime_state.shared_heartbeat_result,
        timeout_retry_evidence=tuple(runtime_state.timeout_retry_evidence),
        timeout_reporting_failures=runtime_state.timeout_reporting_failures,
    )


__all__ = (
    "TimeoutSweepRuntimeState",
    "collect_timeout_sweep_runtime_state",
    "evaluate_timeout_sweep_runtime_state",
)
