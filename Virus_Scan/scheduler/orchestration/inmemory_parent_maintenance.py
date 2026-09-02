"""Parent-side in-memory scheduler maintenance sweeps."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import monitor_recoverable_exceptions
from Virus_Scan.scheduler.orchestration.inmemory_empty_drain_reconciliation import (
    EmptyDrainReconciliationDecision,
    unsupported_empty_drain_reconciliation,
)

from Virus_Scan.runtime.api import log_error, record_scheduler_suppressed
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.evidence.inmemory_progress_logging import ProgressLogger, maybe_log_inmemory_progress
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_plain_instance_dict
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail, scheduler_int, scheduler_nonnegative_int
from Virus_Scan.scheduler.workers.inmemory_worker_death import retry_jobs_owned_by_dead_workers, snapshot_inmemory_worker_liveness
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity import enforce_worker_memory_toxicity
from Virus_Scan.scheduler.workers.process_termination import terminate_idle_inmemory_worker_for_toxicity
from Virus_Scan.scheduler.workers.heartbeat import read_shared_heartbeat
from Virus_Scan.scheduler.orchestration.inmemory_parent_timeout_maintenance import run_inmemory_parent_timeout_maintenance
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, MutableSequence, MutableSet
    from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import ActiveJobs, EvidenceRecord, InMemoryMemoryPolicyProtocol, InMemoryRecoveryMaintenanceProtocol, JobRecords, StartWaitBudget
@dataclass(frozen=True)
class InMemoryMaintenanceRequest:
    procs: MutableSequence[object]
    active: ActiveJobs
    terminal: MutableSet[int]
    retry_job: Callable[..., object]
    worker_metrics: dict[object, object]
    memory_policy: InMemoryMemoryPolicyProtocol
    recovery: InMemoryRecoveryMaintenanceProtocol
    job_records: JobRecords
    worker_heartbeats: dict[object, object]
    heartbeat_table: object
    heartbeat_flags: object
    state_index: object
    max_queued_unstarted: int
    queued_start_timeout_sec: float
    assigned_start_timeout_sec: float
    heartbeat_stale_sec: float
    progress_stale_sec: float
    base_pf_timeout: float
    cancel_grace_sec: float
    start_wait_budget: StartWaitBudget
    stage_is_pre_execution: Callable[[object], bool]
    ewma_state: dict[str, float]
    now: float
    last_log: float
    progress_every: int
    total_files: int
    pending: object
    last_progress_total: int
    logging_module: ProgressLogger
    time_time: Callable[[], float]
    time_monotonic_ns: Callable[[], int]
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))

@dataclass(frozen=True)
class InMemoryMaintenanceResult:
    last_log: float
    last_progress_total: int
    timeout_retry_evidence: tuple[EvidenceRecord, ...] = ()
    timeout_reporting_failures: tuple[EvidenceRecord, ...] = ()
    def __post_init__(self) -> None:
        object.__setattr__(self, "timeout_retry_evidence", immutable_tuple(self.timeout_retry_evidence))
        object.__setattr__(self, "timeout_reporting_failures", immutable_tuple(self.timeout_reporting_failures))

def run_inmemory_parent_maintenance(request: InMemoryMaintenanceRequest) -> InMemoryMaintenanceResult:
    timeout_retry_evidence: tuple[EvidenceRecord, ...] = ()
    timeout_reporting_failures: tuple[EvidenceRecord, ...] = ()
    initial_retry_evidence_count = request.recovery.retry_evidence_count()
    initial_cancel_evidence_count = request.recovery.cancel_evidence_count()
    try:
        retry_jobs_owned_by_dead_workers(
            procs=request.procs,
            active=request.active,
            terminal=request.terminal,
            retry_job=request.retry_job,
        )
    except request.recoverable_exceptions as exc:
        log_error(str.__add__("in-memory worker-death retry sweep failed: ", scheduler_error_detail(exc)))
    try:
        enforce_worker_memory_toxicity(
            procs=request.procs,
            active=request.active,
            terminal=request.terminal,
            worker_metrics=request.worker_metrics,
            rss_limit_mb=request.memory_policy.rss_limit_mb,
            cancel_job=request.recovery.request_cancel_only,
            idle_worker_terminator=terminate_idle_inmemory_worker_for_toxicity,
            recoverable_exceptions=request.recoverable_exceptions,
            record_suppressed=record_scheduler_suppressed,
            job_records=request.job_records,
        )
    except request.recoverable_exceptions as exc:
        log_error(str.__add__("in-memory worker memory-toxicity sweep failed: ", scheduler_error_detail(exc)))
    timeout_maintenance = run_inmemory_parent_timeout_maintenance(
        request,
        initial_retry_evidence_count=initial_retry_evidence_count,
        initial_cancel_evidence_count=initial_cancel_evidence_count,
        read_heartbeat=read_shared_heartbeat,
    )
    timeout_retry_evidence = tuple(timeout_maintenance.timeout_retry_evidence)
    timeout_reporting_failures = tuple(timeout_maintenance.timeout_reporting_failures)
    worker_liveness = snapshot_inmemory_worker_liveness(procs=request.procs)
    pending_count, _pending_supported = _owned_container_len(request.pending)
    progress_state = maybe_log_inmemory_progress(
        now=request.now,
        last_log_time=request.last_log,
        progress_every=request.progress_every,
        completed=request.recovery.completed,
        total_files=request.total_files,
        active_count=len(request.active),
        pending_count=pending_count,
        live_workers=worker_liveness.live_count,
        logical_inflight_count=request.state_index.logical_inflight_count(),
        queued_unstarted_count=request.state_index.queued_unstarted_count(),
        logger=request.logging_module,
        last_progress_total=request.last_progress_total,
        log_error=log_error,
    )
    return InMemoryMaintenanceResult(
        last_log=progress_state.last_log_time,
        last_progress_total=progress_state.last_progress_total,
        timeout_retry_evidence=tuple(timeout_retry_evidence),
        timeout_reporting_failures=tuple(timeout_reporting_failures),
    )


def _owned_container_len(value: object) -> tuple[int, bool]:
    if value is None:
        return 0, True
    items = no_hook_mapping_items(value)
    if items is not None:
        return len(items), True
    if type(value) is list:
        return list.__len__(value), True
    if type(value) is tuple:
        return tuple.__len__(value), True
    if type(value) is set:
        return set.__len__(value), True
    if type(value) is frozenset:
        return frozenset.__len__(value), True
    return 0, False


def _empty_drain_completed_count(value: object) -> int:
    return scheduler_nonnegative_int(
        value,
        reason="unsafe_empty_drain_completed",
    )


def _recovery_completed_count(recovery: object) -> tuple[int, bool]:
    data = no_hook_plain_instance_dict(recovery)
    if data is not None:
        completed = dict.get(data, "completed", 0)
        return _empty_drain_completed_count(completed), True
    items = no_hook_mapping_items(recovery)
    if items is not None:
        for key, value in items:
            if type(key) is str and str.__str__(key) == "completed":
                return _empty_drain_completed_count(value), True
        return 0, True
    return 0, False


def empty_drain_reconciliation_decision(*, pending: object, active: object, state_index: object, recovery: object, submitted: int, total_files: int) -> EmptyDrainReconciliationDecision:
    pending_count, pending_supported = _owned_container_len(pending)
    active_count, active_supported = _owned_container_len(active)
    completed_count, recovery_supported = _recovery_completed_count(recovery)
    submitted_count, _submitted_reason = scheduler_int(submitted, default=0, minimum=0, reason="unsafe_empty_drain_submitted")
    total_count, _total_reason = scheduler_int(total_files, default=0, minimum=0, reason="unsafe_empty_drain_total_files")
    unsupported = tuple(name for name, ok in (("pending", pending_supported), ("active", active_supported), ("recovery", recovery_supported)) if not ok)
    if unsupported:
        return unsupported_empty_drain_reconciliation(unsupported)
    should_reconcile = pending_count == 0 and active_count == 0 and state_index.queued_or_active_count() == 0 and completed_count < total_count and submitted_count >= total_count
    return EmptyDrainReconciliationDecision(should_reconcile)


def should_reconcile_empty_drain(*, pending: object, active: object, state_index: object, recovery: object, submitted: int, total_files: int) -> bool:
    return empty_drain_reconciliation_decision(pending=pending, active=active, state_index=state_index, recovery=recovery, submitted=submitted, total_files=total_files).should_reconcile
