"""Result assembly steps for in-memory parent runtime setup."""
from __future__ import annotations

from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import (
    InMemoryParentRuntimeSetupRequest,
    InMemoryParentRuntimeSetupResult,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup_support import (
    build_parent_runtime_result,
    log_parent_runtime_setup,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup_steps import (
    InMemoryParentRuntimeBootstrap,
    InMemoryParentRuntimeRegistry,
)


def build_parent_runtime_from_parts(
    request: InMemoryParentRuntimeSetupRequest,
    bootstrap: InMemoryParentRuntimeBootstrap,
    registry: InMemoryParentRuntimeRegistry,
) -> InMemoryParentRuntimeSetupResult:
    return build_parent_runtime_result(
        request=request,
        environ=bootstrap.environ,
        requested=bootstrap.requested,
        workers=bootstrap.workers,
        ctx=bootstrap.ctx,
        worker_threads=bootstrap.worker_threads,
        base_worker_threads=bootstrap.base_worker_threads,
        thread_scale_cpu=bootstrap.thread_scale_cpu,
        capacity_plan=bootstrap.capacity_plan,
        task_q=bootstrap.task_q,
        result_q=bootstrap.result_q,
        live_state=bootstrap.live_state,
        runtime_snapshot=bootstrap.runtime_snapshot,
        timeout_config=bootstrap.timeout_config,
        pending=registry.pending,
        job_records=registry.job_records,
        lifecycle_epoch=registry.lifecycle_epoch,
        recovery=registry.recovery,
    )


def log_parent_runtime_bootstrap(
    request: InMemoryParentRuntimeSetupRequest,
    bootstrap: InMemoryParentRuntimeBootstrap,
) -> None:
    log_parent_runtime_setup(
        request=request,
        requested=bootstrap.requested,
        workers=bootstrap.workers,
        worker_threads=bootstrap.worker_threads,
        base_worker_threads=bootstrap.base_worker_threads,
        thread_scale_cpu=bootstrap.thread_scale_cpu,
        capacity_plan=bootstrap.capacity_plan,
        runtime_snapshot=bootstrap.runtime_snapshot,
    )


__all__ = ("build_parent_runtime_from_parts", "log_parent_runtime_bootstrap")
