"""Bounded helper ownership for in-memory parent runtime setup."""
from __future__ import annotations

import ctypes as _ctypes
import logging

from Virus_Scan.routing.context_identity import RoutingEvidenceContext
from Virus_Scan.runtime.api import get_init_value
from Virus_Scan.orchestration.worker_runtime_descriptors import build_worker_mitre_runtime_descriptor
from Virus_Scan.orchestration.worker_runtime_descriptors import build_worker_yara_runtime_descriptor
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import InMemoryParentRuntimeSetupRequest, InMemoryParentRuntimeSetupResult
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup_values import int_log_value as _int_log_value, optional_float_log_value as _optional_float_log_value, stage_limits_log_value as _stage_limits_log_value
from Virus_Scan.scheduler.queue.inmemory_lifecycle_journal import InMemoryLifecycleJournal
from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.runtime.worker_capacity import inmemory_worker_thread_max as _umige_inmemory_worker_thread_max
from Virus_Scan.scheduler.timeout.inmemory_memory_policy import build_inmemory_worker_memory_policy
from Virus_Scan.scheduler.timeout.longtask_controller import FileScanTimeoutError
from Virus_Scan.scheduler.timeout.timeout_budget import annotate_timeout_result, compute_timeout_budget
from Virus_Scan.scheduler.workers.inmemory_runtime_config import build_inmemory_runtime_config_snapshot
from Virus_Scan.storage import scan_cache_repository

def build_parent_runtime_snapshot(
    *,
    request: InMemoryParentRuntimeSetupRequest,
    ctx: object,
    environ: object,
    workers: int,
    capacity_plan: object,
    worker_threads: int,
    base_worker_threads: int,
) -> object:
    mitre_descriptor = build_worker_mitre_runtime_descriptor(request.scan_session_snapshot)
    yara_descriptor = build_worker_yara_runtime_descriptor(request.scan_session_snapshot)
    routing_evidence_context = RoutingEvidenceContext.build(request.root)
    return build_inmemory_runtime_config_snapshot(
        ctx=ctx,
        ctypes_module=_ctypes,
        environ=environ,
        recoverable_exceptions=request.recoverable_exceptions,
        get_init_value=get_init_value,
        file_count=len(request.all_files),
        workers=workers,
        logical_slots=capacity_plan.logical_slots,
        strict=request.strict,
        yara_enabled=request.yara_enabled,
        scan_cache_enabled=scan_cache_repository().enabled(),
        yara_runtime_descriptor=yara_descriptor,
        scan_session_snapshot=request.scan_session_snapshot,
        routing_evidence_context=routing_evidence_context,
        per_file_timeout_sec=request.per_file_timeout_sec,
        slow_file_warn_sec=request.slow_file_warn_sec,
        worker_threads=worker_threads,
        worker_threads_base=base_worker_threads,
        worker_threads_max=_umige_inmemory_worker_thread_max(env=environ),
        timeout_budget_factory=compute_timeout_budget,
        timeout_result_annotator=annotate_timeout_result,
        timeout_error_type=FileScanTimeoutError,
        mitre_initializer=mitre_descriptor.initializer,
        mitre_root=mitre_descriptor.root,
        mitre_enabled=mitre_descriptor.enabled,
        mitre_available=mitre_descriptor.available,
        mitre_repository_digest=mitre_descriptor.repository_digest,
        mitre_dataset_version=mitre_descriptor.dataset_version,
        mitre_unavailable_reason=mitre_descriptor.unavailable_reason,
    )
def build_parent_recovery_coordinator(
    *,
    request: InMemoryParentRuntimeSetupRequest,
    job_records: object,
    active: object,
    pending: object,
    results: object,
    failed: object,
    terminal: object,
    lifecycle_journal: InMemoryLifecycleJournal,
    state_index: object,
    timeout_config: object,
    runtime_snapshot: object,
    worker_error_result: object,
) -> InMemoryRecoveryCoordinator:
    cancel_table = runtime_snapshot.cancel_table
    cancel_generation = cancel_table.get("generation") if isinstance(cancel_table, dict) else None
    cancel_flags = cancel_table.get("flags") if isinstance(cancel_table, dict) else None
    return InMemoryRecoveryCoordinator(
        job_records=job_records,
        active=active,
        pending=pending,
        results=results,
        failed=failed,
        terminal=terminal,
        lifecycle_journal=lifecycle_journal,
        state_index=state_index,
        max_job_retries=timeout_config.max_job_retries,
        cancel_table=cancel_table,
        cancel_generation=cancel_generation,
        cancel_flags=cancel_flags,
        cancel_stall_poison_mask=int(runtime_snapshot.heartbeat_flags.cancel_stall_poison_mask),
        total_files=len(request.all_files),
        worker_error_result=worker_error_result,
    )
def log_parent_runtime_setup(
    *,
    request: InMemoryParentRuntimeSetupRequest,
    requested: int,
    workers: int,
    worker_threads: int,
    base_worker_threads: int,
    thread_scale_cpu: object,
    capacity_plan: object,
    runtime_snapshot: object,
) -> None:
    logging.info(
        "bulk scan scheduler=inmemory-longlived-threaded processes=%s/%s "
        "threads_per_process=%s base_threads=%s cpu=%s logical_slots=%s "
        "files=%s queue_depth=%s max_inflight=%s max_queued_unstarted=%s "
        "stage_limits=%s raw=triage-gated thread_scaling=cpu-first",
        _int_log_value(workers),
        _int_log_value(requested),
        _int_log_value(worker_threads),
        _int_log_value(base_worker_threads),
        _optional_float_log_value(thread_scale_cpu),
        _int_log_value(capacity_plan.logical_slots),
        _int_log_value(len(request.all_files)),
        _int_log_value(capacity_plan.queue_depth),
        _int_log_value(capacity_plan.max_inflight),
        _int_log_value(capacity_plan.max_queued_unstarted),
        _stage_limits_log_value(runtime_snapshot.stage_limits),
    )
def build_parent_runtime_result(
    *,
    request: InMemoryParentRuntimeSetupRequest,
    environ: object,
    requested: int,
    workers: int,
    ctx: object,
    worker_threads: int,
    base_worker_threads: int,
    thread_scale_cpu: object,
    capacity_plan: object,
    task_q: object,
    result_q: object,
    live_state: object,
    runtime_snapshot: object,
    timeout_config: object,
    pending: object,
    job_records: object,
    lifecycle_epoch: object,
    recovery: InMemoryRecoveryCoordinator,
) -> InMemoryParentRuntimeSetupResult:
    return InMemoryParentRuntimeSetupResult(
        requested=requested,
        workers=workers,
        ctx=ctx,
        manager=None,
        worker_threads=worker_threads,
        base_worker_threads=base_worker_threads,
        thread_scale_cpu=thread_scale_cpu,
        logical_slots=capacity_plan.logical_slots,
        queue_depth=capacity_plan.queue_depth,
        task_q=task_q,
        result_q=result_q,
        live_state=live_state,
        state_index=live_state.state_index,
        ewma_state=live_state.ewma_state,
        cfg=runtime_snapshot.as_worker_config(),
        heartbeat_flags=runtime_snapshot.heartbeat_flags,
        stage_limits=dict(runtime_snapshot.stage_limits),
        heartbeat_table=runtime_snapshot.heartbeat_table,
        routing_evidence_context=runtime_snapshot.routing_evidence_context,
        memory_policy=build_inmemory_worker_memory_policy(environ),
        timeout_config_evidence=tuple(timeout_config.config_evidence),
        max_job_retries=timeout_config.max_job_retries,
        base_pf_timeout=timeout_config.base_file_timeout_seconds,
        queued_start_timeout_sec=timeout_config.queued_start_timeout_seconds,
        assigned_start_timeout_sec=timeout_config.assigned_start_timeout_seconds,
        heartbeat_stale_sec=timeout_config.heartbeat_stale_seconds,
        progress_stale_sec=timeout_config.progress_stale_seconds,
        cancel_grace_sec=timeout_config.cancel_grace_seconds,
        pending=pending,
        job_records=job_records,
        active=live_state.active,
        worker_heartbeats=live_state.worker_heartbeats,
        worker_metrics=live_state.worker_metrics,
        done=live_state.done,
        failed=live_state.failed,
        terminal=live_state.terminal,
        results=live_state.results,
        procs=live_state.processes,
        lifecycle_epoch=lifecycle_epoch,
        max_inflight=capacity_plan.max_inflight,
        max_queued_unstarted=capacity_plan.max_queued_unstarted,
        recovery=recovery,
    )
__all__ = (
    "build_parent_recovery_coordinator",
    "build_parent_runtime_result",
    "build_parent_runtime_snapshot",
    "log_parent_runtime_setup",
)
