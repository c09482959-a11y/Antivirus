from __future__ import annotations

from typing import Callable, Iterable, Tuple

from Virus_Scan.contracts.env_config import float_env
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_boundary import exact_active_worker_items
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_publisher_steps import (
    WorkerHeartbeatPublishEvidence,
    publish_one_active_worker_heartbeat,
)


def publish_active_worker_heartbeats(
    *,
    active_items: Iterable[Tuple[object, object]],
    cfg: dict,
    cancel_table: object,
    heartbeat_table: object,
    heartbeat_flags: object,
    completed_jobs: int,
    cancel_requested: Callable[[object, str, int], bool],
    update_shared_heartbeat: Callable[..., object],
    process_id: int,
    now_hb: float,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> object:
    """Worker-owned heartbeat publication for active in-memory worker tasks.

    Returns True when heartbeat publication detects a poisoned/retiring worker and
    the worker loop should stop accepting new jobs.
    """
    should_stop = False
    default_rss_limit = float_env("UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB", 2048.0, 0.0, None)
    for _fut, _meta in exact_active_worker_items(active_items):
        should_stop = publish_one_active_worker_heartbeat(
            meta=_meta,
            cfg=cfg,
            cancel_table=cancel_table,
            heartbeat_table=heartbeat_table,
            heartbeat_flags=heartbeat_flags,
            completed_jobs=completed_jobs,
            cancel_requested=cancel_requested,
            update_shared_heartbeat=update_shared_heartbeat,
            process_id=process_id,
            now_hb=now_hb,
            default_rss_limit=default_rss_limit,
            recoverable_exceptions=recoverable_exceptions,
            record_suppressed=record_suppressed,
        ) or should_stop
    return should_stop


__all__ = (
    "WorkerHeartbeatPublishEvidence",
    "publish_active_worker_heartbeats",
)
