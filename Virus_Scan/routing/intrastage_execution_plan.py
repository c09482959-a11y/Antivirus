"""Canonical environment-to-session intrastage concurrency planning."""
from __future__ import annotations

from Virus_Scan.contracts.env_config import bool_env, int_env, str_env
from Virus_Scan.contracts.intrastage_execution import IntrastageExecutionPlan
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.runtime.api import STAGE_PARALLEL_DEFAULT_WORKERS


def intrastage_enabled() -> bool:
    return bool_env("UMIGE_INTRASTAGE_PARALLEL", default=True)


def stage_parallel_enabled() -> bool:
    return bool_env("UMIGE_STAGE_PARALLEL", default=True)


def stage_parallel_workers() -> int:
    default_workers, reason = no_hook_exact_nonnegative_int(
        STAGE_PARALLEL_DEFAULT_WORKERS,
        default=1,
        reason="stage_parallel_default_rejected",
        non_finite_reason="stage_parallel_default_rejected",
    )
    if reason or default_workers < 1:
        default_workers = 1
    return int_env("UMIGE_STAGE_PARALLEL_WORKERS", default_workers, 1, 256)


def intrastage_default_backend() -> str:
    backend = str_env("UMIGE_INTRASTAGE_BACKEND", "thread").strip().lower()
    return backend if backend in {"thread", "process"} else "thread"


def intrastage_serial_task_threshold() -> int:
    return int_env("UMIGE_INTRASTAGE_SERIAL_THRESHOLD", 2, 1, 64)


def intrastage_max_process_task_bytes() -> int:
    return int_env("UMIGE_INTRASTAGE_MAX_PROCESS_TASK_BYTES", 256 * 1024, 4096, 16 * 1024 * 1024)


def intrastage_max_pending_tasks(workers: object = None) -> int:
    resolved_workers = stage_parallel_workers() if workers is None else workers
    worker_count, reason = no_hook_exact_nonnegative_int(
        resolved_workers,
        default=1,
        reason="intrastage_pending_worker_count_rejected",
        non_finite_reason="intrastage_pending_worker_count_rejected",
    )
    if reason or worker_count < 1:
        worker_count = 1
    default_pending = max(worker_count, worker_count * 4)
    return int_env("UMIGE_INTRASTAGE_MAX_PENDING", default_pending, worker_count, 4096)


def resolve_intrastage_execution_plan(
    *, scheduler_mode: object, scheduler_worker_count: object,
) -> IntrastageExecutionPlan:
    if type(scheduler_mode) is not str:
        raise TypeError("intrastage_scheduler_mode_invalid")
    if type(scheduler_worker_count) is not int or type(scheduler_worker_count) is bool:
        raise TypeError("intrastage_scheduler_worker_count_invalid")
    workers = stage_parallel_workers()
    return IntrastageExecutionPlan(
        scheduler_mode=scheduler_mode,
        scheduler_worker_count=scheduler_worker_count,
        stage_parallel_enabled=stage_parallel_enabled(),
        intrastage_enabled=intrastage_enabled(),
        default_backend=intrastage_default_backend(),
        intrastage_workers=workers,
        serial_task_threshold=intrastage_serial_task_threshold(),
        max_pending_tasks=intrastage_max_pending_tasks(workers),
        max_process_task_bytes=intrastage_max_process_task_bytes(),
    )


__all__ = (
    "intrastage_default_backend",
    "intrastage_enabled",
    "intrastage_max_pending_tasks",
    "intrastage_max_process_task_bytes",
    "intrastage_serial_task_threshold",
    "resolve_intrastage_execution_plan",
    "stage_parallel_enabled",
    "stage_parallel_workers",
)
