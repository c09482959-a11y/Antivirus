"""Bounded construction steps for in-memory runtime config snapshots."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int
from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags, build_inmemory_heartbeat_flags
from Virus_Scan.scheduler.workers.inmemory_runtime_config_support import (
    build_ipc_tables,
    build_stage_limits,
    build_stage_semaphores,
)

_SCHEDULER_ZERO_INT = 0
_SCHEDULER_ZERO_FLOAT = 0.0


@dataclass(frozen=True, slots=True)
class RuntimeConfigIpcState:
    """IPC tables, stage semaphores, and construction evidence."""

    heartbeat_flags: InMemoryHeartbeatFlags
    cancel_table: Mapping[str, object] | None
    heartbeat_table: Mapping[str, object] | None
    stage_limits: Mapping[str, int]
    stage_semaphores: Mapping[str, object]
    failure_evidence: tuple[Mapping[str, object], ...]


@dataclass(frozen=True, slots=True)
class RuntimeConfigScalarState:
    """Strict scalar scheduler configuration values."""

    strict: bool
    per_file_timeout_sec: int
    slow_file_warn_sec: float
    worker_threads: int
    worker_threads_base: int
    worker_threads_max: int


def build_runtime_config_ipc_state(
    *,
    ctx: object,
    ctypes_module: object,
    environ: Mapping[str, str],
    recoverable_exceptions: tuple[type[BaseException], ...],
    get_init_value: object,
    file_count: int,
    workers: int,
    logical_slots: int,
) -> RuntimeConfigIpcState:
    """Build IPC-owned scheduler tables and record construction evidence."""

    failure_evidence: list[Mapping[str, object]] = []
    heartbeat_flags = build_inmemory_heartbeat_flags(get_init_value)
    cancel_table, heartbeat_table, ipc_evidence = build_ipc_tables(
        ctx=ctx,
        ctypes_module=ctypes_module,
        file_count=file_count,
        recoverable_exceptions=recoverable_exceptions,
    )
    failure_evidence.extend(ipc_evidence)
    stage_limits, limit_evidence = build_stage_limits(
        environ=environ,
        workers=workers,
        logical_slots=logical_slots,
        recoverable_exceptions=recoverable_exceptions,
    )
    failure_evidence.extend(limit_evidence)
    stage_semaphores, semaphore_evidence = build_stage_semaphores(
        ctx=ctx,
        stage_limits=stage_limits,
        recoverable_exceptions=recoverable_exceptions,
    )
    failure_evidence.extend(semaphore_evidence)
    return RuntimeConfigIpcState(
        heartbeat_flags=heartbeat_flags,
        cancel_table=cancel_table,
        heartbeat_table=heartbeat_table,
        stage_limits=stage_limits,
        stage_semaphores=stage_semaphores,
        failure_evidence=tuple(failure_evidence),
    )


def parse_runtime_config_scalars(
    *,
    strict: object,
    per_file_timeout_sec: object,
    slow_file_warn_sec: object,
    worker_threads: object,
    worker_threads_base: object,
    worker_threads_max: object,
) -> RuntimeConfigScalarState:
    """Normalize strict scalar values for an immutable runtime snapshot."""

    strict_value, strict_reason = scheduler_bool(
        strict,
        default=False,
        reason="inmemory_runtime_strict_rejected",
    )
    per_file_timeout_value, _per_file_timeout_reason = scheduler_int(
        per_file_timeout_sec,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_runtime_per_file_timeout_rejected",
    )
    slow_file_warn_value, _slow_file_warn_reason = scheduler_float(
        slow_file_warn_sec,
        default=_SCHEDULER_ZERO_FLOAT,
        minimum=0.0,
        reason="inmemory_runtime_slow_file_warn_rejected",
    )
    worker_threads_value, _worker_threads_reason = scheduler_int(
        worker_threads,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_runtime_worker_threads_rejected",
    )
    worker_threads_base_value, _worker_threads_base_reason = scheduler_int(
        worker_threads_base,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_runtime_worker_threads_base_rejected",
    )
    worker_threads_max_value, _worker_threads_max_reason = scheduler_int(
        worker_threads_max,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_runtime_worker_threads_max_rejected",
    )
    return RuntimeConfigScalarState(
        strict=strict_value if strict_reason == "" else False,
        per_file_timeout_sec=per_file_timeout_value,
        slow_file_warn_sec=slow_file_warn_value,
        worker_threads=worker_threads_value,
        worker_threads_base=worker_threads_base_value,
        worker_threads_max=worker_threads_max_value,
    )


__all__ = (
    "RuntimeConfigIpcState",
    "RuntimeConfigScalarState",
    "build_runtime_config_ipc_state",
    "parse_runtime_config_scalars",
)
