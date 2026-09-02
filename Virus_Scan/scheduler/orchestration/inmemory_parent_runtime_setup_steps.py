"""Bounded setup steps for the in-memory parent scheduler runtime."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import (
    InMemoryParentRuntimeSetupRequest,
)
from Virus_Scan.scheduler.workers.inmemory_capacity_plan import build_inmemory_capacity_plan
from Virus_Scan.scheduler.workers.inmemory_lifecycle_policy import deterministic_lifecycle_epoch
from Virus_Scan.scheduler.ownership.inmemory_job_registry import build_inmemory_job_registry
from Virus_Scan.scheduler.ownership.inmemory_live_state import build_inmemory_live_scheduler_state
from Virus_Scan.scheduler.queue.inmemory_lifecycle_journal import InMemoryLifecycleJournal
from Virus_Scan.scheduler.orchestration.inmemory_timeout_config_job_evidence import (
    attach_timeout_config_evidence_to_job_records,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup_support import (
    build_parent_recovery_coordinator,
    build_parent_runtime_snapshot,
)
from Virus_Scan.scheduler.workers.inmemory_worker_pool import start_inmemory_worker_pool
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup_values import (
    positive_process_count as _positive_process_count,
)
from Virus_Scan.scheduler.runtime.multiprocessing_context import get_scheduler_multiprocessing_context
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.runtime.execution_memory_capacity import execution_memory_snapshot
from Virus_Scan.scheduler.runtime.worker_capacity import (
    inmemory_adaptive_worker_thread_count as _umige_inmemory_adaptive_worker_thread_count,
    inmemory_worker_thread_count as _umige_inmemory_worker_thread_count,
    longlived_worker_count as _umige_longlived_worker_count,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_config import build_inmemory_timeout_config
from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget


@dataclass(frozen=True, slots=True)
class InMemoryParentRuntimeBootstrap:
    requested: int
    environ: object
    workers: int
    ctx: object
    worker_threads: int
    base_worker_threads: int
    thread_scale_cpu: object
    capacity_plan: object
    task_q: object
    result_q: object
    live_state: object
    runtime_snapshot: object
    timeout_config: object


@dataclass(frozen=True, slots=True)
class InMemoryParentRuntimeRegistry:
    pending: object
    job_records: object
    lifecycle_epoch: object
    recovery: object


def build_parent_runtime_bootstrap(
    request: InMemoryParentRuntimeSetupRequest,
    *,
    scheduler_context_factory: Callable[
        [],
        object,
    ] = get_scheduler_multiprocessing_context,
) -> InMemoryParentRuntimeBootstrap:
    requested = _positive_process_count(request.process_count)
    environ = scheduler_environment_snapshot(request.environ)
    workers = _umige_longlived_worker_count(
        requested,
        total_files=len(request.all_files),
        env=environ,
        memory_snapshot=execution_memory_snapshot(),
    )
    ctx = scheduler_context_factory()
    base_worker_threads = _umige_inmemory_worker_thread_count(env=environ)
    worker_threads, thread_scale_cpu = _umige_inmemory_adaptive_worker_thread_count(
        base_worker_threads,
        workers=workers,
        total_files=len(request.all_files),
        env=environ,
    )
    capacity_plan = build_inmemory_capacity_plan(
        environ,
        workers=workers,
        worker_threads=worker_threads,
    )
    task_q = ctx.Queue(maxsize=capacity_plan.queue_depth)
    result_q = ctx.Queue(maxsize=max(capacity_plan.logical_slots * 8, 64))
    live_state = build_inmemory_live_scheduler_state()
    runtime_snapshot = build_parent_runtime_snapshot(
        request=request,
        ctx=ctx,
        environ=environ,
        workers=workers,
        capacity_plan=capacity_plan,
        worker_threads=worker_threads,
        base_worker_threads=base_worker_threads,
    )
    timeout_config = build_inmemory_timeout_config(
        environ,
        per_file_timeout_sec=request.per_file_timeout_sec,
    )
    return InMemoryParentRuntimeBootstrap(
        requested=requested,
        environ=environ,
        workers=workers,
        ctx=ctx,
        worker_threads=worker_threads,
        base_worker_threads=base_worker_threads,
        thread_scale_cpu=thread_scale_cpu,
        capacity_plan=capacity_plan,
        task_q=task_q,
        result_q=result_q,
        live_state=live_state,
        runtime_snapshot=runtime_snapshot,
        timeout_config=timeout_config,
    )


def build_parent_runtime_registry(
    request: InMemoryParentRuntimeSetupRequest,
    bootstrap: InMemoryParentRuntimeBootstrap,
    *,
    worker_error_result: Callable[
        ...,
        object,
    ] = make_scheduler_worker_error_result,
) -> InMemoryParentRuntimeRegistry:
    pending, job_records = build_inmemory_job_registry(
        request.all_files,
        per_file_timeout_sec=request.per_file_timeout_sec,
        timeout_budget_factory=compute_timeout_budget,
    )
    attach_timeout_config_evidence_to_job_records(
        job_records,
        tuple(bootstrap.timeout_config.config_evidence),
    )
    live_state = bootstrap.live_state
    lifecycle_epoch = deterministic_lifecycle_epoch(request.root, request.all_files)
    recovery = build_parent_recovery_coordinator(
        request=request,
        job_records=job_records,
        active=live_state.active,
        pending=pending,
        results=live_state.results,
        failed=live_state.failed,
        terminal=live_state.terminal,
        lifecycle_journal=InMemoryLifecycleJournal(epoch=lifecycle_epoch),
        state_index=live_state.state_index,
        timeout_config=bootstrap.timeout_config,
        runtime_snapshot=bootstrap.runtime_snapshot,
        worker_error_result=worker_error_result,
    )
    return InMemoryParentRuntimeRegistry(
        pending=pending,
        job_records=job_records,
        lifecycle_epoch=lifecycle_epoch,
        recovery=recovery,
    )


def start_parent_runtime_workers(bootstrap: InMemoryParentRuntimeBootstrap) -> None:
    startup = start_inmemory_worker_pool(
        context=bootstrap.ctx,
        worker_count=bootstrap.workers,
        task_queue=bootstrap.task_q,
        result_queue=bootstrap.result_q,
        worker_config=bootstrap.runtime_snapshot.as_worker_config(),
    )
    bootstrap.live_state.processes.extend(startup.processes)



__all__ = (
    "InMemoryParentRuntimeBootstrap",
    "InMemoryParentRuntimeRegistry",
    "build_parent_runtime_bootstrap",
    "build_parent_runtime_registry",
    "start_parent_runtime_workers",
)
