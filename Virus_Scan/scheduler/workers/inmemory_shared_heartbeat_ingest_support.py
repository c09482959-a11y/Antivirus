"""Support helpers for bounded shared heartbeat ingestion."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest, LifecycleRequestRecorder

from typing import Callable, Mapping, MutableMapping, MutableSet

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.workers.inmemory_shared_heartbeat_apply import apply_shared_heartbeat_row
from Virus_Scan.scheduler.workers.inmemory_shared_heartbeat_row import parse_shared_heartbeat_row
from Virus_Scan.scheduler.workers.shared_heartbeat_evidence import record_shared_heartbeat_failure

_SCHEDULER_ZERO_INT = 0


def initial_shared_heartbeat_counts() -> dict[str, int]:
    return {
        "observed": 0,
        "cancel_requested": 0,
        "heartbeat_read_failures": 0,
        "heartbeat_row_failures": 0,
        "lifecycle_record_failures": 0,
        "cancel_request_failures": 0,
    }


def shared_heartbeat_state_containers_accepted(
    *,
    job_records: object,
    active: object,
    terminal: object,
    worker_heartbeats: object,
    worker_metrics: object,
    active_job_ids: object,
) -> bool:
    return not (
        type(job_records) is not dict
        or type(active) is not dict
        or type(terminal) not in (set, frozenset)
        or type(worker_heartbeats) is not dict
        or type(worker_metrics) is not dict
        or type(active_job_ids) is not tuple
        or any(type(job_id) is not int or type(job_id) is bool or job_id < 0 for job_id in active_job_ids)
    )


def rejected_shared_heartbeat_counts() -> dict[str, int]:
    _failure(
        "heartbeat_ingest_state",
        "unknown",
        None,
        ValueError("shared heartbeat state containers rejected"),
    )
    counts = initial_shared_heartbeat_counts()
    counts["heartbeat_row_failures"] = 1
    return counts


def _failure(operation: str, job_id: object, attempt: object, exc: BaseException) -> None:
    record_shared_heartbeat_failure(
        operation=operation,
        job_id=job_id,
        generation=attempt,
        exc=exc,
    )


def ingest_shared_heartbeat_rows(
    *,
    counts: dict[str, int],
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
) -> None:
    for job_id in active_job_ids:
        record = dict.get(job_records, job_id)
        if type(record) is not dict:
            counts["heartbeat_row_failures"] += 1
            _failure("heartbeat_ingest_row", job_id, None, ValueError("shared_heartbeat_job_record_rejected"))
            continue
        if set.__contains__(terminal, job_id):
            continue
        attempt, attempt_reason = scheduler_int(
            scheduler_mapping_value(record, "attempt", default=_SCHEDULER_ZERO_INT),
            default=_SCHEDULER_ZERO_INT,
            minimum=0,
            reason="shared_heartbeat_attempt_rejected",
        )
        if attempt_reason:
            counts["heartbeat_row_failures"] += 1
            _failure("heartbeat_ingest_row", job_id, None, ValueError(attempt_reason))
            continue
        try:
            heartbeat_row = read_heartbeat(heartbeat_table, job_id, attempt)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            counts["heartbeat_read_failures"] += 1
            _failure("heartbeat_ingest_read", job_id, attempt, exc)
            continue
        if heartbeat_row is None:
            continue
        _apply_shared_heartbeat_row(
            counts=counts,
            job_id=job_id,
            attempt=attempt,
            record=record,
            active=active,
            worker_heartbeats=worker_heartbeats,
            worker_metrics=worker_metrics,
            heartbeat_row=heartbeat_row,
            heartbeat_flags=heartbeat_flags,
            cancel_job=cancel_job,
            lifecycle_recorder=lifecycle_recorder,
            monotonic_ns=monotonic_ns,
            wall_time=wall_time,
        )


def _apply_shared_heartbeat_row(
    *,
    counts: dict[str, int],
    job_id: int,
    attempt: int,
    record: MutableMapping[str, object],
    active: MutableMapping[int, MutableMapping[str, object]],
    worker_heartbeats: MutableMapping[int, float],
    worker_metrics: MutableMapping[int, Mapping[str, object]],
    heartbeat_row: object,
    heartbeat_flags: object,
    cancel_job: Callable[..., object],
    lifecycle_recorder: LifecycleRequestRecorder,
    monotonic_ns: Callable[[], int],
    wall_time: Callable[[], float],
) -> None:
    try:
        parsed = parse_shared_heartbeat_row(
            row=heartbeat_row,
            record=record,
            heartbeat_flags=heartbeat_flags,
            monotonic_ns=monotonic_ns,
            wall_time=wall_time,
        )
        apply_shared_heartbeat_row(
            parsed=parsed,
            job_id=job_id,
            record=record,
            active=active,
            worker_heartbeats=worker_heartbeats,
            worker_metrics=worker_metrics,
        )
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        counts["heartbeat_row_failures"] += 1
        _failure("heartbeat_ingest_row", job_id, attempt, exc)
        return
    if parsed.made_progress:
        try:
            lifecycle_recorder(
                InMemoryLifecycleRecordRequest(
                    job_id=job_id,
                    attempt=attempt,
                    transition="shared_heartbeat",
                    worker_pid=parsed.pid,
                    state=parsed.state,
                )
            )
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            counts["lifecycle_record_failures"] += 1
            _failure("heartbeat_ingest_lifecycle", job_id, attempt, exc)
    counts["observed"] += 1
    if parsed.flags & parsed.poison_mask:
        try:
            cancel_job(job_id, "worker_poisoned_or_retiring", pid=parsed.pid)
            counts["cancel_requested"] += 1
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            counts["cancel_request_failures"] += 1
            _failure("heartbeat_ingest_cancel", job_id, attempt, exc)


__all__ = (
    "ingest_shared_heartbeat_rows",
    "initial_shared_heartbeat_counts",
    "rejected_shared_heartbeat_counts",
    "shared_heartbeat_state_containers_accepted",
)
