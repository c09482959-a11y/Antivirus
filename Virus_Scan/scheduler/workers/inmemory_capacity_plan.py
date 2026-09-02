"""Worker-owned in-memory capacity and queue-depth planning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.workers.dispatch_value_support import positive_worker_int
from Virus_Scan.scheduler.runtime.env_policy import float_env, int_env


@dataclass(frozen=True)
class InMemoryCapacityPlan:
    logical_slots: int
    queue_depth: int
    max_inflight: int
    max_queued_unstarted: int


def build_inmemory_capacity_plan(environ: Mapping[str, str], *, workers: int, worker_threads: int) -> InMemoryCapacityPlan:
    safe_workers = positive_worker_int(workers, "inmemory_capacity_workers_rejected")
    safe_worker_threads = positive_worker_int(worker_threads, "inmemory_capacity_worker_threads_rejected")
    logical_slots = max(1, safe_workers * safe_worker_threads)
    default_queue_depth = logical_slots * 8
    queue_depth = max(
        logical_slots * 8,
        int_env(environ, "UMIGE_INMEMORY_QUEUE_DEPTH", default_queue_depth, (ValueError, TypeError)),
    )
    max_inflight_mult = float_env(environ, "UMIGE_INMEMORY_MAX_INFLIGHT_MULT", 1.20, (ValueError, TypeError))
    max_inflight = max(
        logical_slots,
        int(max_inflight_mult * logical_slots),
    )
    default_unstarted = max(safe_workers * 2, logical_slots // 4)
    max_queued_unstarted = max(
        1,
        int_env(environ, "UMIGE_INMEMORY_MAX_QUEUED_UNSTARTED", default_unstarted, (ValueError, TypeError)),
    )
    return InMemoryCapacityPlan(
        logical_slots=logical_slots,
        queue_depth=queue_depth,
        max_inflight=max_inflight,
        max_queued_unstarted=max_queued_unstarted,
    )
