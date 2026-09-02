"""Capacity/runtime directory ownership for process-queue startup."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import monitor_int

from Virus_Scan.scheduler.runtime.backpressure_policy import cpu_count_safe
from Virus_Scan.scheduler.runtime.process_queue_runtime_policy import compute_process_queue_child_capacity, process_queue_dynamic_feed_enabled
from Virus_Scan.scheduler.runtime.queue_filesystem import scheduler_runtime_temp_dir as _umige_runtime_temp_dir
from Virus_Scan.scheduler.runtime.queue_filesystem import scheduler_runtime_work_queue_dir as _umige_runtime_work_queue_dir
from Virus_Scan.scheduler.runtime.writable_paths import create_process_queue_runtime_dirs
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.runtime.execution_memory_capacity import execution_memory_snapshot

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class ProcessQueueStartupCapacity:
    requested_process_count: int
    process_count: int
    process_capacity: object
    runtime_dirs: object
    queue_dir: Path
    outputs_dir: Path
    dynamic_queue_feed: bool


def build_process_queue_startup_capacity(*, all_files: tuple[str, ...], requested_process_count: int, recoverable_exceptions: tuple[type[BaseException], ...]) -> ProcessQueueStartupCapacity:
    """Compute startup capacity and externally writable runtime directories."""
    normalized_requested = monitor_int(requested_process_count, default=1, minimum=1, reason="process_queue_startup_capacity_requested_rejected")
    env_snapshot = scheduler_environment_snapshot()
    process_capacity = compute_process_queue_child_capacity(
        requested_process_count=normalized_requested,
        file_count=len(all_files),
        cpu_count=cpu_count_safe(),
        env=env_snapshot,
        recoverable_exceptions=recoverable_exceptions,
        memory_snapshot=execution_memory_snapshot(),
    )
    runtime_dirs = create_process_queue_runtime_dirs(
        runtime_temp_dir=_umige_runtime_temp_dir,
        runtime_work_queue_dir=_umige_runtime_work_queue_dir,
    )
    return ProcessQueueStartupCapacity(
        requested_process_count=process_capacity.requested,
        process_count=process_capacity.process_count,
        process_capacity=process_capacity,
        runtime_dirs=runtime_dirs,
        queue_dir=runtime_dirs.queue_dir,
        outputs_dir=runtime_dirs.outputs_dir,
        dynamic_queue_feed=process_queue_dynamic_feed_enabled(env_snapshot, recoverable_exceptions),
    )
