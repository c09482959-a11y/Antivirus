"""Runtime-owned process worker capacity calculations."""
from __future__ import annotations

import os
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_value_snapshot
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.runtime.execution_memory_capacity import ExecutionMemorySnapshot, process_memory_worker_cap


def _empty_scheduler_environment() -> dict[str, str]:
    return {}


def _record_capacity_rejection(*, setting: str, value: object, policy_default: object, reason: str) -> None:
    record_suppressed_failure(
        "scheduler_process_capacity_integer_rejected",
        ValueError(reason), domain="scheduler",
        context={"setting": setting, "reason": reason, "value_type": no_hook_type_name(value),
                 "value": scheduler_value_snapshot(value, field_name=setting),
                 "policy_default": scheduler_value_snapshot(policy_default, field_name=setting + "_policy_default")},
    )


def _policy_int_value(value: object, *, policy_default: int, minimum: int = 0, maximum: int | None = None, setting: str) -> int:
    parsed, reason = scheduler_int(value, default=policy_default, minimum=minimum, maximum=maximum, reason="scheduler_process_capacity_integer_rejected")
    if reason:
        _record_capacity_rejection(setting=setting, value=value, policy_default=policy_default, reason=reason)
    return parsed


def _scheduler_environment(env: object) -> object:
    try:
        source = scheduler_environment_snapshot(env)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _record_capacity_rejection(setting="scheduler_process_environment", value=env, policy_default={}, reason=no_hook_type_name(exc))
        return _empty_scheduler_environment()
    if source.get("scheduler_mapping_unavailable", False) is True:
        _record_capacity_rejection(setting="scheduler_process_environment", value=env, policy_default={}, reason="scheduler_process_capacity_environment_rejected")
        return _empty_scheduler_environment()
    return source


def memory_bounded_process_workers(candidate: object, *, env: object, memory_snapshot: ExecutionMemorySnapshot) -> int:
    count = _policy_int_value(candidate, policy_default=1, minimum=1, setting="candidate_worker_count")
    memory_cap = process_memory_worker_cap(_scheduler_environment(env), memory_snapshot)
    if memory_cap is None:
        return count
    if memory_cap < 1:
        raise RuntimeError("scheduler_process_memory_capacity_exhausted")
    return min(count, memory_cap)


def process_queue_is_child_shard(env: Mapping[str, str]) -> bool:
    return _scheduler_environment(env).get("UMIGE_PROCESS_SHARD", "") == "1"


def default_process_scheduler_workers(*, env: Mapping[str, str], cpu_count: int, recoverable_exceptions: tuple[type[BaseException], ...], memory_snapshot: ExecutionMemorySnapshot) -> int:
    del recoverable_exceptions
    source = _scheduler_environment(env)
    configured = _policy_int_value(source.get("UMIGE_PROCESS_QUEUE_MAX_CHILDREN", "64"), policy_default=64, minimum=1, setting="UMIGE_PROCESS_QUEUE_MAX_CHILDREN")
    cpus = _policy_int_value(cpu_count, policy_default=1, minimum=1, setting="cpu_count")
    return memory_bounded_process_workers(max(2, min(configured, max(cpus * 4, 4))), env=source, memory_snapshot=memory_snapshot)


def default_filesystem_queue_workers(*, cpu_count: int, env: Mapping[str, str], memory_snapshot: ExecutionMemorySnapshot) -> int:
    candidate = max(2, min(_policy_int_value(cpu_count, policy_default=2, minimum=1, setting="filesystem_cpu_count"), 32))
    return memory_bounded_process_workers(candidate, env=env, memory_snapshot=memory_snapshot)


def scheduler_windows_processpool_cap() -> int:
    try:
        cpu = os.cpu_count() or 4
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _record_capacity_rejection(setting="os_cpu_count", value=None, policy_default=4, reason=no_hook_type_name(exc))
        cpu = 4
    cpu_count = cpu if type(cpu) is int and type(cpu) is not bool and cpu > 0 else 4
    return 61 if os.name == "nt" else max(1, min(256, cpu_count * 8))


def longlived_worker_count(requested: object, total_files: object=0, *, env: object, memory_snapshot: ExecutionMemorySnapshot) -> int:
    source = _scheduler_environment(env)
    requested_count = _policy_int_value(requested, policy_default=0, minimum=0, setting="requested_worker_count")
    if requested_count <= 0:
        requested_count = _policy_int_value(source.get("UMIGE_PROCESS_QUEUE_MAX_CHILDREN", "64"), policy_default=64, minimum=1, setting="UMIGE_PROCESS_QUEUE_MAX_CHILDREN")
    hard_cap = _policy_int_value(source.get("UMIGE_LONG_LIVED_PROCESS_CAP", scheduler_windows_processpool_cap()), policy_default=scheduler_windows_processpool_cap(), minimum=1, setting="UMIGE_LONG_LIVED_PROCESS_CAP")
    if os.name == "nt":
        hard_cap = min(hard_cap, 61)
    total_count = _policy_int_value(total_files, policy_default=0, minimum=0, setting="total_files")
    candidate = min(requested_count, hard_cap, total_count) if total_count > 0 else min(requested_count, hard_cap)
    return memory_bounded_process_workers(max(1, candidate), env=source, memory_snapshot=memory_snapshot)


__all__ = ("default_filesystem_queue_workers", "default_process_scheduler_workers", "longlived_worker_count", "memory_bounded_process_workers", "process_queue_is_child_shard", "scheduler_windows_processpool_cap")
