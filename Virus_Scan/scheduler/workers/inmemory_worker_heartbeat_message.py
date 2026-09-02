"""Parent-side in-memory worker heartbeat message ownership."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import LifecycleRequestRecorder

from typing import Callable, MutableMapping, MutableSet

from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_application import (
    apply_inmemory_worker_heartbeat_progress,
    apply_inmemory_worker_poison_signal,
)
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_payload import (
    parse_inmemory_worker_heartbeat_payload,
    resolve_inmemory_worker_heartbeat_time,
)
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_values import (
    heartbeat_int as _heartbeat_int,
    heartbeat_text as _heartbeat_text,
)
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_decisions import (
    worker_heartbeat_attempt_decision,
    worker_heartbeat_record_decision,
)

_INMEMORY_HEARTBEAT_LOOKUP_STATE_REJECTED = "inmemory heartbeat lookup state rejected"
_INMEMORY_HEARTBEAT_RECORD_REJECTED = "inmemory heartbeat record rejected"
_INMEMORY_HEARTBEAT_MUTATION_STATE_REJECTED = "inmemory heartbeat mutation state rejected"
_INMEMORY_HEARTBEAT_RECORD_ATTEMPT_REJECTED = "inmemory heartbeat record attempt rejected"
_INMEMORY_HEARTBEAT_RECORD_STATE_REJECTED = "inmemory heartbeat record state rejected"


def ingest_worker_heartbeat_message(
    *,
    message: object,
    job_records: MutableMapping[int, MutableMapping[str, object]],
    active: MutableMapping[int, MutableMapping[str, object]],
    terminal: MutableSet[int],
    worker_heartbeats: MutableMapping[int, float],
    worker_metrics: MutableMapping[int, MutableMapping[str, object]],
    heartbeat_flags: object,
    history_transition: Callable[..., object],
    cancel_job: Callable[..., object],
    lifecycle_recorder: LifecycleRequestRecorder,
    wall_time: Callable[[], float],
) -> bool:
    """Validate and apply one parent-side heartbeat before mutating live state."""

    payload = parse_inmemory_worker_heartbeat_payload(message)
    if type(job_records) is not dict or type(terminal) not in (set, frozenset):
        raise ValueError(_INMEMORY_HEARTBEAT_LOOKUP_STATE_REJECTED)
    record = dict.get(job_records, payload.job_id)
    record_decision = worker_heartbeat_record_decision(
        record=record,
        terminal=terminal,
        job_id=payload.job_id,
    )
    if not record_decision.value:
        return record_decision.value
    if type(record) is not dict:
        raise ValueError(_INMEMORY_HEARTBEAT_RECORD_REJECTED)
    if (
        type(active) is not dict
        or type(worker_heartbeats) is not dict
        or type(worker_metrics) is not dict
        or type(heartbeat_flags) is not InMemoryHeartbeatFlags
    ):
        raise ValueError(_INMEMORY_HEARTBEAT_MUTATION_STATE_REJECTED)
    record_attempt = _heartbeat_int(dict.get(record, "attempt", 0), field_name="record_attempt")
    if record_attempt is None:
        raise ValueError(_INMEMORY_HEARTBEAT_RECORD_ATTEMPT_REJECTED)
    attempt_decision = worker_heartbeat_attempt_decision(
        record_attempt=record_attempt,
        attempt=payload.attempt,
    )
    if not attempt_decision.value:
        return attempt_decision.value
    heartbeat_time = resolve_inmemory_worker_heartbeat_time(payload, wall_time)
    state = _heartbeat_text(
        dict.get(record, "state"),
        field_name="record_state",
        missing_text="unknown",
    )
    if state is None:
        raise ValueError(_INMEMORY_HEARTBEAT_RECORD_STATE_REJECTED)
    apply_inmemory_worker_heartbeat_progress(
        payload=payload,
        record=record,
        active=active,
        worker_heartbeats=worker_heartbeats,
        worker_metrics=worker_metrics,
        heartbeat_time=heartbeat_time,
        state=state,
        lifecycle_recorder=lifecycle_recorder,
    )
    apply_inmemory_worker_poison_signal(
        payload=payload,
        record=record,
        heartbeat_flags=heartbeat_flags,
        history_transition=history_transition,
        cancel_job=cancel_job,
        wall_time=wall_time,
    )
    return True
