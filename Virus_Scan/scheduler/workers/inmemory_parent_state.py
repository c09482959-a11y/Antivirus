"""Parent-side in-memory worker state message ownership."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest, LifecycleRequestRecorder

from typing import TypeAlias, cast, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int
from Virus_Scan.scheduler.workers.inmemory_heartbeat_progress import heartbeat_progress_signature
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import safe_worker_message_preview
from Virus_Scan.scheduler.workers.inmemory_parent_state_decisions import WorkerJobRecordDecision, WorkerStateApplyDecision, WorkerTimestampDecision

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping
_MISSING = object()
WorkerRecord: TypeAlias = dict[str, object]
WorkerMessageItems: TypeAlias = tuple[object, ...]
WorkerStateMessage: TypeAlias = tuple[object, int, object, int, float, int, int]

def _worker_state_int(value: object, *, field_name: str, minimum: int | None = 0) -> int:
    parsed, reason = scheduler_int(value, default=0, minimum=minimum, reason="worker_state_" + field_name + "_rejected")
    if reason != "":
        raise ValueError("worker state message " + field_name + " rejected: " + reason)
    return parsed

def _parse_worker_state_message(message: object) -> WorkerStateMessage:
    if type(message) is tuple:
        items = message
    elif type(message) is list:
        items = tuple(message)
    else:
        raise ValueError("unsupported worker state message type=" + no_hook_type_name(message))
    count = len(items)
    if count >= 7:
        kind, job_id, path, pid, ts, attempt, thread_id = items[:7]
    elif count >= 6:
        kind, job_id, path, pid, ts, attempt = items[:6]
        thread_id = 0
    elif count == 5:
        kind, job_id, path, pid, ts = items
        attempt = 0
        thread_id = 0
    else:
        raise ValueError("short worker state message len=" + int.__str__(count) + " preview=" + safe_worker_message_preview(items))
    parsed_job_id = _worker_state_int(job_id, field_name="job_id")
    parsed_pid = _worker_state_int(pid, field_name="pid")
    parsed_ts, ts_reason = scheduler_float(
        ts,
        default=0.0,
        minimum=0.0,
        reason="worker_state_timestamp_rejected",
    )
    if ts_reason != "":
        raise ValueError("worker state message timestamp rejected: " + ts_reason)
    return (kind, parsed_job_id, path, parsed_pid, parsed_ts, _worker_state_int(attempt, field_name="attempt"), _worker_state_int(thread_id, field_name="thread_id"))

def _owned_mapping_value(mapping: object, key: object, default: object = _MISSING) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for item_key, item_value in items:
        if item_key == key:
            return item_value
    return default

def _owned_job_record_decision(job_records: object, job_id: int) -> WorkerJobRecordDecision:
    record = _owned_mapping_value(job_records, job_id, None)
    if type(record) is dict:
        return WorkerJobRecordDecision(record=record, accepted=True, reason="")
    return WorkerJobRecordDecision(record=None, accepted=False, reason="missing_or_unsupported_job_record")

def _owned_job_record(job_records: object, job_id: int) -> WorkerRecord | None:
    return _owned_job_record_decision(job_records, job_id).record

def _record_attempt(record: WorkerRecord) -> int:
    value = _owned_mapping_value(record, "attempt", 0)
    parsed, reason = scheduler_int(value, default=0, minimum=0, reason="worker_record_attempt_rejected")
    if reason != "":
        return -1
    return parsed

def _record_assigned_at_decision(record: WorkerRecord) -> WorkerTimestampDecision:
    value = _owned_mapping_value(record, "assigned_at", 0.0)
    parsed, reason = scheduler_float(value, default=0.0, minimum=0.0, reason="worker_record_assigned_at_rejected")
    if reason != "":
        return WorkerTimestampDecision(value=0.0, accepted=False, reason=reason)
    return WorkerTimestampDecision(value=parsed, accepted=True, reason="")

def _record_assigned_at(record: WorkerRecord) -> float:
    return _record_assigned_at_decision(record).value

def _worker_state_application_decision(
    rec: WorkerRecord | None,
    terminal: object,
    job_id: int,
    attempt: int,
) -> WorkerStateApplyDecision:
    if rec is None:
        return WorkerStateApplyDecision(applied=False, reason="missing_or_unsupported_job_record")
    if type(terminal) is set:
        terminal_contains = job_id in cast("set[object]", terminal)
    elif type(terminal) is frozenset:
        terminal_contains = job_id in cast("frozenset[object]", terminal)
    else:
        terminal_contains = True
    if terminal_contains:
        return WorkerStateApplyDecision(applied=False, reason="terminal_job_rejected")
    if _record_attempt(rec) != attempt:
        return WorkerStateApplyDecision(applied=False, reason="attempt_mismatch")
    return WorkerStateApplyDecision(applied=True, reason="")

def mark_worker_assigned_from_message(
    *,
    message: object,
    job_records: MutableMapping[int, WorkerRecord],
    active: MutableMapping[int, WorkerRecord],
    terminal: object,
    mark_retry_admitted: Callable[..., object],
    lifecycle_recorder: LifecycleRequestRecorder,
    state_index: object,
) -> bool:
    _kind, job_id, path, pid, ts, attempt, _thread_id = _parse_worker_state_message(message)
    rec = _owned_job_record(job_records, job_id)
    apply_decision = _worker_state_application_decision(rec, terminal, job_id, attempt)
    if not apply_decision.applied:
        return apply_decision.applied
    rec = cast("WorkerRecord", rec)
    rec["state"] = "assigned"
    rec["pid"] = pid
    rec["assigned_at"] = ts
    mark_retry_admitted(rec, attempt=attempt, now=ts)
    lifecycle_recorder(
        InMemoryLifecycleRecordRequest(
            job_id=job_id,
            attempt=attempt,
            transition="assigned",
            worker_pid=pid,
            state="assigned",
        )
    )
    active[job_id] = {"file": path, "pid": pid, "assigned": ts, "start": 0.0, "attempt": attempt, "state": "assigned"}
    state_index.sync_record(job_id, rec, due_at=ts)
    return True

def mark_worker_running_from_message(
    *,
    message: object,
    job_records: MutableMapping[int, WorkerRecord],
    active: MutableMapping[int, WorkerRecord],
    terminal: object,
    worker_heartbeats: MutableMapping[int, float],
    mark_retry_admitted: Callable[..., object],
    lifecycle_recorder: LifecycleRequestRecorder,
    state_index: object,
) -> bool:
    _kind, job_id, path, pid, ts, attempt, thread_id = _parse_worker_state_message(message)
    rec = _owned_job_record(job_records, job_id)
    apply_decision = _worker_state_application_decision(rec, terminal, job_id, attempt)
    if not apply_decision.applied:
        return apply_decision.applied
    rec = cast("WorkerRecord", rec)
    rec["state"] = "running"
    rec["pid"] = pid
    rec["thread_id"] = thread_id
    rec["running_at"] = ts
    rec["started_at"] = ts
    rec["last_heartbeat"] = ts
    rec["last_progress_time"] = ts
    rec["last_progress_signature"] = heartbeat_progress_signature(
        stage="scan",
        progress_counter=0,
        bytes_processed=0,
        last_progress_ns=0,
    )
    rec["last_progress_ns"] = 0
    rec["stage"] = "scan"
    mark_retry_admitted(rec, attempt=attempt, now=ts)
    lifecycle_recorder(
        InMemoryLifecycleRecordRequest(
            job_id=job_id,
            attempt=attempt,
            transition="running",
            worker_pid=pid,
            state="running",
        )
    )
    worker_heartbeats[pid] = ts
    active[job_id] = {"file": path, "pid": pid, "assigned": _record_assigned_at(rec), "start": ts, "attempt": attempt, "state": "running", "last_heartbeat": ts, "heartbeat_seq": 0, "stage": "scan"}
    state_index.sync_record(job_id, rec, due_at=ts)
    return True
