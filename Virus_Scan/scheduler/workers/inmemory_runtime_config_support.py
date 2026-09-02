"""Support builders for immutable in-memory scheduler runtime configuration."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.workers.inmemory_runtime_env import env_int_required


def scheduler_config_failure(
    reason: str,
    error: BaseException,
    *,
    component: str,
) -> dict[str, object]:
    return {
        "stage": "inmemory_runtime_config",
        "state": "failed",
        "error_category": reason,
        "error_source": "scheduler.workers.inmemory_runtime_config",
        "message": reason,
        "context": {
            "component": component,
            "exception_type": no_hook_type_name(error),
        },
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
        "fatal": False,
    }


def default_stage_limits(*, workers: int, logical_slots: int) -> dict[str, int]:
    worker_count, worker_reason = scheduler_int(
        workers,
        default=1,
        minimum=1,
        reason="scheduler_stage_default_workers_rejected",
    )
    slot_count, slot_reason = scheduler_int(
        logical_slots,
        default=1,
        minimum=1,
        reason="scheduler_stage_default_slots_rejected",
    )
    if worker_reason != "":
        worker_count = 1
    if slot_reason != "":
        slot_count = 1
    return {
        "yara": max(4, slot_count // 2),
        "image": max(8, slot_count // 2),
        "archive": max(4, worker_count // 2),
        "dotnet": max(4, worker_count),
        "raw": max(16, slot_count),
        "generic": max(32, slot_count),
    }


def build_ipc_tables(
    *,
    ctx: object,
    ctypes_module: object,
    file_count: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[Mapping[str, object] | None, Mapping[str, object] | None, tuple[Mapping[str, object], ...]]:
    failure_evidence: list[Mapping[str, object]] = []
    cancel_table = None
    try:
        cancel_table = {
            "generation": ctx.Array("i", file_count, lock=False),
            "flags": ctx.Array("i", file_count, lock=False),
        }
    except recoverable_exceptions as error:
        failure_evidence.append(
            scheduler_config_failure(
                "scheduler_cancel_table_unavailable",
                error,
                component="cancel_table",
            )
        )

    heartbeat_table = None
    try:
        heartbeat_table = {
            "monotonic_ns": ctx.Array(ctypes_module.c_ulonglong, file_count, lock=False),
            "pid": ctx.Array("i", file_count, lock=False),
            "thread_id": ctx.Array("i", file_count, lock=False),
            "generation": ctx.Array("i", file_count, lock=False),
            "stage": ctx.Array("i", file_count, lock=False),
            "progress_counter": ctx.Array("i", file_count, lock=False),
            "bytes_processed": ctx.Array(ctypes_module.c_ulonglong, file_count, lock=False),
            "last_progress_ns": ctx.Array(ctypes_module.c_ulonglong, file_count, lock=False),
            "flags": ctx.Array("i", file_count, lock=False),
            "rss_mb": ctx.Array("d", file_count, lock=False),
            "completed_jobs": ctx.Array("i", file_count, lock=False),
        }
    except recoverable_exceptions as error:
        failure_evidence.append(
            scheduler_config_failure(
                "scheduler_heartbeat_table_unavailable",
                error,
                component="heartbeat_table",
            )
        )
    return cancel_table, heartbeat_table, tuple(failure_evidence)


def build_stage_limits(
    *,
    environ: Mapping[str, str],
    workers: int,
    logical_slots: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[dict[str, int], tuple[Mapping[str, object], ...]]:
    defaults = default_stage_limits(workers=workers, logical_slots=logical_slots)
    try:
        return {
            "yara": env_int_required(environ, "UMIGE_STAGE_LIMIT_YARA", env_int_required(environ, "UMIGE_GLOBAL_YARA_SEM", defaults["yara"])),
            "image": env_int_required(environ, "UMIGE_STAGE_LIMIT_IMAGE", env_int_required(environ, "UMIGE_GLOBAL_IMAGE_SEM", defaults["image"])),
            "archive": env_int_required(environ, "UMIGE_STAGE_LIMIT_ARCHIVE", env_int_required(environ, "UMIGE_GLOBAL_ARCHIVE_SEM", defaults["archive"])),
            "dotnet": env_int_required(environ, "UMIGE_STAGE_LIMIT_DOTNET", env_int_required(environ, "UMIGE_GLOBAL_DOTNET_SEM", defaults["dotnet"])),
            "raw": env_int_required(environ, "UMIGE_STAGE_LIMIT_RAW", env_int_required(environ, "UMIGE_GLOBAL_RAW_SEM", defaults["raw"])),
            "generic": env_int_required(environ, "UMIGE_STAGE_LIMIT_GENERIC", env_int_required(environ, "UMIGE_GLOBAL_GENERIC_STAGE_SEM", defaults["generic"])),
        }, ()
    except recoverable_exceptions as error:
        return defaults, (
            scheduler_config_failure(
                "scheduler_stage_limits_invalid",
                error,
                component="stage_limits",
            ),
        )


def build_stage_semaphores(
    *,
    ctx: object,
    stage_limits: Mapping[str, int],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[dict[str, object], tuple[Mapping[str, object], ...]]:
    try:
        limit_items = no_hook_mapping_items(stage_limits)
        if limit_items is None:
            raise ValueError("scheduler_stage_limits_mapping_rejected")
        semaphores: dict[str, object] = {}
        for name, limit in limit_items:
            if type(name) is not str:
                raise ValueError("scheduler_stage_limit_name_rejected")
            parsed, reason = scheduler_int(
                limit,
                default=1,
                minimum=1,
                reason="scheduler_stage_limit_rejected",
            )
            if reason != "":
                raise ValueError(reason)
            semaphores[str.__str__(name)] = ctx.BoundedSemaphore(parsed)
    except recoverable_exceptions as error:
        return {}, (
            scheduler_config_failure(
                "scheduler_stage_semaphores_unavailable",
                error,
                component="stage_semaphores",
            ),
        )
    else:
        return semaphores, ()


__all__ = (
    "build_ipc_tables",
    "build_stage_limits",
    "build_stage_semaphores",
)
