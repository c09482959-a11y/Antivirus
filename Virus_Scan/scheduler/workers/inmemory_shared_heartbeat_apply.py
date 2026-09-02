"""Apply a fully validated shared heartbeat row."""
from __future__ import annotations

from typing import Mapping, MutableMapping, TYPE_CHECKING


if TYPE_CHECKING:
    from Virus_Scan.scheduler.workers.inmemory_shared_heartbeat_row import SharedHeartbeatRow


def apply_shared_heartbeat_row(
    *,
    parsed: SharedHeartbeatRow,
    job_id: int,
    record: MutableMapping[str, object],
    active: MutableMapping[int, MutableMapping[str, object]],
    worker_heartbeats: MutableMapping[int, float],
    worker_metrics: MutableMapping[int, Mapping[str, object]],
) -> None:
    record.update(
        {
            "last_heartbeat": parsed.heartbeat_time,
            "heartbeat_seq": parsed.progress_counter,
            "heartbeat_flags": parsed.flags,
            "stage": parsed.stage,
            "bytes_processed": parsed.bytes_processed,
            "worker_rss_mb": parsed.rss_mb,
        }
    )
    worker_heartbeats[parsed.pid] = parsed.heartbeat_time
    worker_metrics[parsed.pid] = {
        "rss_mb": parsed.rss_mb,
        "completed_jobs": parsed.completed_jobs,
        "last_seen": parsed.heartbeat_time,
    }
    if parsed.made_progress:
        record["last_progress_signature"] = parsed.signature
        record["last_progress_time"] = parsed.heartbeat_time
        record["last_progress_ns"] = parsed.last_progress_ns
    active_info = active.get(job_id)
    if type(active_info) is dict:
        active_info.update(
            {
                "last_heartbeat": parsed.heartbeat_time,
                "heartbeat_seq": parsed.progress_counter,
                "stage": parsed.stage,
            }
        )


__all__ = ("apply_shared_heartbeat_row",)
