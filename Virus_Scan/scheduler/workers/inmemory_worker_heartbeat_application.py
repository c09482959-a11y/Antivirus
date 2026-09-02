"""Worker heartbeat state application helpers."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest, LifecycleRequestRecorder

from typing import Callable, MutableMapping

from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_heartbeat_progress import (
    heartbeat_progress_changed,
    heartbeat_progress_signature,
)
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_payload import (
    InMemoryWorkerHeartbeatPayload,
)
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_values import (
    heartbeat_float as _heartbeat_float,
    wall_time_value as _wall_time_value,
)

_INMEMORY_HEARTBEAT_TRANSITION_TIME_REJECTED = "inmemory heartbeat transition time rejected"
_INMEMORY_HEARTBEAT_HISTORY_TRANSITION_REJECTED = "inmemory heartbeat history transition rejected"
_INMEMORY_HEARTBEAT_CANCEL_TIMESTAMP_REJECTED = "inmemory heartbeat cancel timestamp rejected"


def apply_inmemory_worker_heartbeat_progress(
    *,
    payload: InMemoryWorkerHeartbeatPayload,
    record: MutableMapping[str, object],
    active: MutableMapping[int, MutableMapping[str, object]],
    worker_heartbeats: MutableMapping[int, float],
    worker_metrics: MutableMapping[int, MutableMapping[str, object]],
    heartbeat_time: float,
    state: str,
    lifecycle_recorder: LifecycleRequestRecorder,
) -> None:
    """Apply heartbeat progress and metric fields after validation succeeds."""

    signature = heartbeat_progress_signature(
        stage=payload.stage,
        progress_counter=payload.progress_counter,
        bytes_processed=payload.bytes_processed,
        last_progress_ns=payload.last_progress_ns,
    )
    made_progress = heartbeat_progress_changed(record, signature)
    worker_heartbeats[payload.pid] = heartbeat_time
    worker_metrics[payload.pid] = {
        "rss_mb": payload.rss_mb,
        "completed_jobs": payload.completed_jobs,
        "last_seen": heartbeat_time,
        "flags": payload.flags,
    }
    record["last_heartbeat"] = heartbeat_time
    record["heartbeat_seq"] = payload.progress_counter
    record["stage"] = payload.stage
    record["progress_counter"] = payload.progress_counter
    record["bytes_processed"] = payload.bytes_processed
    record["last_progress_ns"] = payload.last_progress_ns
    record["heartbeat_flags"] = payload.flags
    if made_progress:
        lifecycle_recorder(
            InMemoryLifecycleRecordRequest(
                job_id=payload.job_id,
                attempt=payload.attempt,
                transition="heartbeat",
                worker_pid=payload.pid,
                state=state,
            )
        )
        record["last_progress_signature"] = signature
        record["last_progress_time"] = heartbeat_time
        record["cancel_requested_at"] = 0.0
    active_info = dict.get(active, payload.job_id)
    if type(active_info) is dict:
        active_info["last_heartbeat"] = heartbeat_time
        active_info["heartbeat_seq"] = payload.progress_counter
        active_info["stage"] = payload.stage
        active_info["progress_counter"] = payload.progress_counter
        active_info["bytes_processed"] = payload.bytes_processed
        active_info["last_progress_time"] = dict.get(record, "last_progress_time", 0.0)


def apply_inmemory_worker_poison_signal(
    *,
    payload: InMemoryWorkerHeartbeatPayload,
    record: MutableMapping[str, object],
    heartbeat_flags: InMemoryHeartbeatFlags,
    history_transition: Callable[..., object],
    cancel_job: Callable[..., object],
    wall_time: Callable[[], float],
) -> None:
    """Apply poisoned/retire heartbeat cancellation evidence when requested."""

    poison_mask = scheduler_exact_attr(
        heartbeat_flags,
        "poisoned_or_retire_mask",
        owner_type=InMemoryHeartbeatFlags,
        default=0,
    )
    if not payload.flags & poison_mask:
        return
    transition_time = _wall_time_value(wall_time)
    if transition_time is None:
        raise ValueError(_INMEMORY_HEARTBEAT_TRANSITION_TIME_REJECTED)
    transitioned = history_transition(
        payload.job_id,
        record,
        "worker_memory_toxic_or_poisoned",
        pid=payload.pid,
        now=transition_time,
        action="worker_memory_signal",
        extra={"rss_mb": payload.rss_mb},
    )
    if type(transitioned) is not dict:
        raise ValueError(_INMEMORY_HEARTBEAT_HISTORY_TRANSITION_REJECTED)
    cancel_requested_at = _heartbeat_float(
        dict.get(transitioned, "cancel_requested_at", 0.0),
        field_name="cancel_requested_at",
    )
    if cancel_requested_at is None:
        raise ValueError(_INMEMORY_HEARTBEAT_CANCEL_TIMESTAMP_REJECTED)
    if cancel_requested_at == 0.0:
        cancel_job(payload.job_id, "worker_memory_toxic", pid=payload.pid)


__all__ = (
    "apply_inmemory_worker_heartbeat_progress",
    "apply_inmemory_worker_poison_signal",
)
