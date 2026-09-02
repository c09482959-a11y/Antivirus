"""Worker heartbeat payload parsing helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_values import (
    heartbeat_float as _heartbeat_float,
    heartbeat_int as _heartbeat_int,
    heartbeat_text as _heartbeat_text,
    wall_time_value as _wall_time_value,
)

_INMEMORY_HEARTBEAT_MESSAGE_CONTAINER_REJECTED = "inmemory heartbeat message container rejected"
_INMEMORY_HEARTBEAT_MESSAGE_TRUNCATED = "inmemory heartbeat message is truncated"
_INMEMORY_HEARTBEAT_SCALAR_REJECTED = "inmemory heartbeat scalar rejected"
_INMEMORY_HEARTBEAT_TIMESTAMP_REJECTED = "inmemory heartbeat timestamp rejected"


@dataclass(frozen=True, slots=True)
class InMemoryWorkerHeartbeatPayload:
    """Typed replayable scalar payload for one worker heartbeat message."""

    job_id: int
    pid: int
    attempt: int
    timestamp_source: object
    progress_counter: int
    stage: str
    bytes_processed: int
    last_progress_ns: int
    flags: int
    rss_mb: float
    completed_jobs: int


def parse_inmemory_worker_heartbeat_payload(message: object) -> InMemoryWorkerHeartbeatPayload:
    """Validate the raw heartbeat IPC message and return typed scalar fields."""

    if type(message) not in (tuple, list):
        raise ValueError(_INMEMORY_HEARTBEAT_MESSAGE_CONTAINER_REJECTED)
    items = no_hook_sequence_items(message)
    if len(items) < 11:
        raise ValueError(_INMEMORY_HEARTBEAT_MESSAGE_TRUNCATED)
    job_id = _heartbeat_int(items[1], field_name="job_id")
    pid = _heartbeat_int(items[3], field_name="pid")
    attempt = _heartbeat_int(items[5], field_name="attempt")
    progress_counter = _heartbeat_int(items[6], field_name="progress_counter")
    stage = _heartbeat_text(items[7], field_name="stage", missing_text="scan")
    bytes_processed = _heartbeat_int(items[8], field_name="bytes_processed")
    last_progress_ns = _heartbeat_int(items[9], field_name="last_progress_ns")
    flags = _heartbeat_int(items[10], field_name="flags")
    rss_mb = _heartbeat_float(items[11], field_name="rss_mb") if len(items) > 11 else 0.0
    completed_jobs = (
        _heartbeat_int(items[12], field_name="completed_jobs")
        if len(items) > 12
        else 0
    )
    if (
        job_id is None
        or pid is None
        or attempt is None
        or progress_counter is None
        or stage is None
        or bytes_processed is None
        or last_progress_ns is None
        or flags is None
        or rss_mb is None
        or completed_jobs is None
    ):
        raise ValueError(_INMEMORY_HEARTBEAT_SCALAR_REJECTED)
    return InMemoryWorkerHeartbeatPayload(
        job_id=job_id,
        pid=pid,
        attempt=attempt,
        timestamp_source=items[4],
        progress_counter=progress_counter,
        stage=stage,
        bytes_processed=bytes_processed,
        last_progress_ns=last_progress_ns,
        flags=flags,
        rss_mb=rss_mb,
        completed_jobs=completed_jobs,
    )


def resolve_inmemory_worker_heartbeat_time(
    payload: InMemoryWorkerHeartbeatPayload,
    wall_time: Callable[[], float],
) -> float:
    """Return the replayable heartbeat timestamp for a parsed payload."""

    timestamp_source = payload.timestamp_source
    if timestamp_source is None or (
        type(timestamp_source) in (int, float)
        and type(timestamp_source) is not bool
        and timestamp_source == 0
    ):
        heartbeat_time = _wall_time_value(wall_time)
    else:
        heartbeat_time = _heartbeat_float(timestamp_source, field_name="timestamp")
    if heartbeat_time is None:
        raise ValueError(_INMEMORY_HEARTBEAT_TIMESTAMP_REJECTED)
    return heartbeat_time


__all__ = (
    "InMemoryWorkerHeartbeatPayload",
    "parse_inmemory_worker_heartbeat_payload",
    "resolve_inmemory_worker_heartbeat_time",
)
