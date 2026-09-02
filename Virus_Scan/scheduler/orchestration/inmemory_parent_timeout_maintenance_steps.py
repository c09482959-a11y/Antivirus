"""Bounded timeout-maintenance steps for the in-memory scheduler parent."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.evidence.inmemory_ewma import update_ewma
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence_projection import attach_timeout_evidence_to_job_records
from Virus_Scan.scheduler.timeout.inmemory_timeout_retry_evidence import evidence_not_already_present
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import enforce_inmemory_timeout_sweep
from Virus_Scan.scheduler.workers.heartbeat import read_shared_heartbeat
from Virus_Scan.scheduler.workers.inmemory_shared_heartbeat import ingest_shared_heartbeats
from Virus_Scan.runtime.api import record_scheduler_suppressed


def run_timeout_sweep_for_parent(
    request: object,
    *,
    read_heartbeat: object = read_shared_heartbeat,
) -> object:
    """Run the timeout sweep with parent-owned dependency wiring."""
    return enforce_inmemory_timeout_sweep(
        state_index=request.state_index,
        job_records=request.job_records,
        active=request.active,
        terminal=request.terminal,
        worker_heartbeats=request.worker_heartbeats,
        worker_metrics=request.worker_metrics,
        heartbeat_table=request.heartbeat_table,
        heartbeat_flags=request.heartbeat_flags,
        read_heartbeat=read_heartbeat,
        cancel_job=request.recovery.request_cancel_only,
        lifecycle_recorder=request.recovery.record_lifecycle_request,
        heartbeat_ingester=ingest_shared_heartbeats,
        monotonic_ns=request.time_monotonic_ns,
        wall_time=request.time_time,
        recovery=request.recovery,
        max_queued_unstarted=request.max_queued_unstarted,
        queued_start_timeout_sec=request.queued_start_timeout_sec,
        assigned_start_timeout_sec=request.assigned_start_timeout_sec,
        heartbeat_stale_sec=request.heartbeat_stale_sec,
        progress_stale_sec=request.progress_stale_sec,
        base_pf_timeout=request.base_pf_timeout,
        cancel_grace_sec=request.cancel_grace_sec,
        start_wait_budget=request.start_wait_budget,
        stage_is_pre_execution=request.stage_is_pre_execution,
        update_ewma=update_ewma,
        ewma_state=request.ewma_state,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=request.recoverable_exceptions,
    )


def collect_parent_timeout_retry_evidence(
    request: object,
    *,
    timeout_sweep_result: object,
    initial_retry_evidence_count: int,
    initial_cancel_evidence_count: int,
) -> tuple[Mapping[str, object], ...]:
    """Merge timeout-sweep, cancel-only, and retry-recovery evidence once."""
    timeout_sweep_evidence = tuple(timeout_sweep_result.timeout_retry_evidence)
    cancel_only_evidence = evidence_not_already_present(
        candidates=request.recovery.cancel_evidence_since(initial_cancel_evidence_count),
        existing=timeout_sweep_evidence,
    )
    retry_recovery_evidence = evidence_not_already_present(
        candidates=request.recovery.retry_evidence_since(initial_retry_evidence_count),
        existing=timeout_sweep_evidence + tuple(cancel_only_evidence),
    )
    return timeout_sweep_evidence + tuple(cancel_only_evidence) + tuple(retry_recovery_evidence)


def attach_parent_timeout_evidence(
    request: object,
    evidence_records: tuple[Mapping[str, object], ...],
) -> None:
    """Attach merged timeout evidence to current job records."""
    attach_timeout_evidence_to_job_records(
        job_records=request.job_records,
        evidence_records=evidence_records,
    )


__all__ = (
    "attach_parent_timeout_evidence",
    "collect_parent_timeout_retry_evidence",
    "run_timeout_sweep_for_parent",
)
