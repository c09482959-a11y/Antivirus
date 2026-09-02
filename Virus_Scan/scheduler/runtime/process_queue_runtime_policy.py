"""Process-queue runtime policy ownership.

This module owns process-queue child capacity, elastic enablement, dynamic-feed
enablement, launch/respawn delays, and monitor timing policy. It keeps runtime
configuration decisions out of the generic scheduler resource limit module.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.runtime.env_policy import bool_env, float_env, int_env
from Virus_Scan.scheduler.runtime.execution_memory_capacity import ExecutionMemorySnapshot
from Virus_Scan.scheduler.runtime.process_worker_capacity import memory_bounded_process_workers

@dataclass(frozen=True)
class ProcessQueueChildCapacity:
    requested: int
    default_cpu_fill_cap: int
    configured_cap: int
    cpu_fill_cap: int
    process_count: int


def compute_process_queue_child_capacity(
    *,
    requested_process_count: int,
    file_count: int,
    cpu_count: int,
    env: Mapping[str, str],
    recoverable_exceptions: tuple[type[BaseException], ...],
    memory_snapshot: ExecutionMemorySnapshot,
) -> ProcessQueueChildCapacity:
    requested, _requested_reason = scheduler_int(
        requested_process_count,
        default=1,
        minimum=1,
        reason="process_queue_requested_count_rejected",
    )
    file_total, _file_reason = scheduler_int(
        file_count,
        default=0,
        minimum=0,
        reason="process_queue_file_count_rejected",
    )
    cpu_total, _cpu_reason = scheduler_int(
        cpu_count,
        default=1,
        minimum=1,
        reason="process_queue_cpu_count_rejected",
    )
    default_cpu_fill_cap = max(requested, min(100, max(cpu_total * 4, requested * 8)))
    configured_cap = int_env(env, "UMIGE_PROCESS_QUEUE_MAX_CHILDREN", 100, recoverable_exceptions)
    cpu_fill_cap = max(1, configured_cap) if configured_cap > 0 else default_cpu_fill_cap
    process_count = memory_bounded_process_workers(
        max(1, min(cpu_fill_cap, max(file_total, requested))),
        env=env,
        memory_snapshot=memory_snapshot,
    )
    return ProcessQueueChildCapacity(
        requested=requested,
        default_cpu_fill_cap=default_cpu_fill_cap,
        configured_cap=configured_cap,
        cpu_fill_cap=cpu_fill_cap,
        process_count=process_count,
    )


def process_queue_dynamic_feed_enabled(env: Mapping[str, str], recoverable_exceptions: tuple[type[BaseException], ...]) -> bool:
    return bool_env(env, "UMIGE_DYNAMIC_QUEUE_FEED", default=True, recoverable_exceptions=recoverable_exceptions)


def elastic_process_queue_enabled(env: Mapping[str, str], recoverable_exceptions: tuple[type[BaseException], ...]) -> bool:
    return bool_env(env, "UMIGE_ELASTIC_QUEUE_SCHEDULER", default=True, recoverable_exceptions=recoverable_exceptions)


def elastic_process_queue_min_workers(
    *,
    env: Mapping[str, str],
    requested_process_count: int,
    process_count: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> int:
    requested, _requested_reason = scheduler_int(
        requested_process_count,
        default=1,
        minimum=1,
        reason="elastic_requested_process_count_rejected",
    )
    total, _total_reason = scheduler_int(
        process_count,
        default=1,
        minimum=1,
        reason="elastic_process_count_rejected",
    )
    policy_min_workers = max(1, min(requested, total))
    value = int_env(env, "UMIGE_ELASTIC_MIN_WORKERS", policy_min_workers, recoverable_exceptions)
    return max(1, min(total, value))


def process_queue_launch_delay(env: Mapping[str, str], recoverable_exceptions: tuple[type[BaseException], ...]) -> float:
    return float_env(env, "UMIGE_PROCESS_QUEUE_LAUNCH_DELAY", 0.03, recoverable_exceptions)


def process_queue_respawn_delay(env: Mapping[str, str], recoverable_exceptions: tuple[type[BaseException], ...]) -> float:
    return float_env(env, "UMIGE_PROCESS_QUEUE_RESPAWN_DELAY", 0.01, recoverable_exceptions)



__all__ = (
    "ProcessQueueChildCapacity",
    "compute_process_queue_child_capacity",
    "elastic_process_queue_enabled",
    "elastic_process_queue_min_workers",
    "process_queue_dynamic_feed_enabled",
    "process_queue_launch_delay",
    "process_queue_respawn_delay",
)
