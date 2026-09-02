"""Worker-owned in-memory active-heartbeat cycle decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, MutableMapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle_decisions import (
    WorkerHeartbeatMappingDecision,
    heartbeat_active_items_decision,
    heartbeat_cfg_decision,
)
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_publisher import publish_active_worker_heartbeats
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle_steps import (
    normalize_heartbeat_cycle_values,
    publish_heartbeat_cycle_values,
)


@dataclass(frozen=True, slots=True)
class InMemoryWorkerHeartbeatCycleResult:
    """Immutable evidence for one heartbeat publication cycle."""

    last_heartbeat_emit: float
    heartbeat_seq: int
    stop_requested: bool
    heartbeat_published: bool
    heartbeat_failure_count: int = 0
    heartbeat_failure_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "heartbeat_failure_evidence", immutable_tuple(self.heartbeat_failure_evidence))


def publish_inmemory_worker_heartbeat_cycle(
    *,
    active: Mapping[object, Mapping[str, object]],
    cfg: Mapping[str, object],
    cancel_table: object,
    heartbeat_table: object,
    heartbeat_flags: MutableMapping[object, object],
    completed_jobs: int,
    cancel_requested: Callable[..., object],
    update_shared_heartbeat: Callable[..., object],
    process_id: int,
    now_hb: float,
    last_heartbeat_emit: float,
    heartbeat_interval: float,
    heartbeat_seq: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
    record_suppressed: Callable[[str, BaseException], object],
) -> InMemoryWorkerHeartbeatCycleResult:
    """Publish active worker heartbeats when the interval has elapsed."""
    values = normalize_heartbeat_cycle_values(
        active=active,
        now_hb=now_hb,
        last_heartbeat_emit=last_heartbeat_emit,
        heartbeat_interval=heartbeat_interval,
        heartbeat_seq=heartbeat_seq,
    )
    if not values.should_publish:
        return InMemoryWorkerHeartbeatCycleResult(
            last_heartbeat_emit=values.last_emit,
            heartbeat_seq=values.seq,
            stop_requested=False,
            heartbeat_published=False,
        )
    publication = publish_heartbeat_cycle_values(
        values=values,
        cfg=cfg,
        cancel_table=cancel_table,
        heartbeat_table=heartbeat_table,
        heartbeat_flags=heartbeat_flags,
        completed_jobs=completed_jobs,
        cancel_requested=cancel_requested,
        update_shared_heartbeat=update_shared_heartbeat,
        heartbeat_publisher=publish_active_worker_heartbeats,
        process_id=process_id,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
    )
    return InMemoryWorkerHeartbeatCycleResult(
        last_heartbeat_emit=publication.now,
        heartbeat_seq=publication.seq + 1,
        stop_requested=publication.stop_requested,
        heartbeat_published=len(publication.heartbeat_failures) == 0,
        heartbeat_failure_count=len(publication.heartbeat_failures),
        heartbeat_failure_evidence=publication.heartbeat_failures,
    )


__all__ = (
    "InMemoryWorkerHeartbeatCycleResult",
    "WorkerHeartbeatMappingDecision",
    "heartbeat_active_items_decision",
    "heartbeat_cfg_decision",
    "publish_inmemory_worker_heartbeat_cycle",
)
