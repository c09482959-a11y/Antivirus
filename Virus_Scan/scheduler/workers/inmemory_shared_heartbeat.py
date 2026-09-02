"""In-memory shared heartbeat ingestion ownership."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import LifecycleRequestRecorder

from dataclasses import dataclass
from typing import Callable, Mapping, MutableMapping, MutableSet

from Virus_Scan.scheduler.workers.inmemory_shared_heartbeat_ingest_support import (
    ingest_shared_heartbeat_rows,
    initial_shared_heartbeat_counts,
    rejected_shared_heartbeat_counts,
    shared_heartbeat_state_containers_accepted,
)


@dataclass(frozen=True, slots=True)
class InMemorySharedHeartbeatIngest:
    observed: int
    cancel_requested: int
    heartbeat_read_failures: int = 0
    heartbeat_row_failures: int = 0
    lifecycle_record_failures: int = 0
    cancel_request_failures: int = 0


def ingest_shared_heartbeats(
    *,
    active_job_ids: tuple[int, ...],
    job_records: MutableMapping[int, MutableMapping[str, object]],
    active: MutableMapping[int, MutableMapping[str, object]],
    terminal: MutableSet[int],
    worker_heartbeats: MutableMapping[int, float],
    worker_metrics: MutableMapping[int, Mapping[str, object]],
    heartbeat_table: object,
    heartbeat_flags: object,
    read_heartbeat: Callable[..., object],
    cancel_job: Callable[..., object],
    lifecycle_recorder: LifecycleRequestRecorder,
    monotonic_ns: Callable[[], int],
    wall_time: Callable[[], float],
) -> InMemorySharedHeartbeatIngest:
    """Refresh only currently active parent-owned job identities."""
    if not shared_heartbeat_state_containers_accepted(
        active_job_ids=active_job_ids,
        job_records=job_records,
        active=active,
        terminal=terminal,
        worker_heartbeats=worker_heartbeats,
        worker_metrics=worker_metrics,
    ):
        return InMemorySharedHeartbeatIngest(**rejected_shared_heartbeat_counts())
    counts = initial_shared_heartbeat_counts()
    ingest_shared_heartbeat_rows(
        counts=counts,
        active_job_ids=active_job_ids,
        job_records=job_records,
        active=active,
        terminal=terminal,
        worker_heartbeats=worker_heartbeats,
        worker_metrics=worker_metrics,
        heartbeat_table=heartbeat_table,
        heartbeat_flags=heartbeat_flags,
        read_heartbeat=read_heartbeat,
        cancel_job=cancel_job,
        lifecycle_recorder=lifecycle_recorder,
        monotonic_ns=monotonic_ns,
        wall_time=wall_time,
    )
    return InMemorySharedHeartbeatIngest(**counts)


__all__ = ("InMemorySharedHeartbeatIngest", "ingest_shared_heartbeats")
