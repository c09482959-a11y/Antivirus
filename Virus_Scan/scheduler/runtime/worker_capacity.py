"""Scheduler runtime worker-capacity public ownership facade.

The bounded runtime implementations live in process/thread/raw capacity modules.
This module preserves the canonical import surface without owning queue, replay,
evidence, or scheduler orchestration behavior.
"""

from __future__ import annotations

from Virus_Scan.scheduler.runtime.process_worker_capacity import (
    default_filesystem_queue_workers,
    default_process_scheduler_workers,
    longlived_worker_count,
    process_queue_is_child_shard,
    scheduler_windows_processpool_cap,
)
from Virus_Scan.scheduler.runtime.raw_worker_capacity import (
    raw_collector_cap,
    raw_worker_pool_cap,
    stage_parallel_workers,
)
from Virus_Scan.scheduler.runtime.thread_worker_capacity import (
    inmemory_adaptive_worker_thread_count,
    inmemory_worker_thread_count,
    inmemory_worker_thread_max,
)

__all__ = (
    "default_filesystem_queue_workers",
    "default_process_scheduler_workers",
    "inmemory_adaptive_worker_thread_count",
    "inmemory_worker_thread_count",
    "inmemory_worker_thread_max",
    "longlived_worker_count",
    "process_queue_is_child_shard",
    "raw_collector_cap",
    "raw_worker_pool_cap",
    "scheduler_windows_processpool_cap",
    "stage_parallel_workers",
)
