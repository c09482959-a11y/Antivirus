"""State helpers for in-memory result completion."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest, LifecycleRequestRecorder

from dataclasses import dataclass
from typing import Callable, MutableMapping, MutableSet

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int
from Virus_Scan.scheduler.internal.no_hook_methods import safe_scheduler_bound_method
from Virus_Scan.scheduler.queue.inmemory_result_completion_projection import (
    bad_result_message_text,
    record_start_time,
    exact_record,
)


@dataclass(frozen=True)
class InMemoryResultMessageParts:
    job_id: object
    path: object
    result: object
    pid: object
    timestamp: object
    attempt: object


def record_suppressed_exception(
    suppressed_recorder: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
    exc: BaseException,
) -> None:
    try:
        suppressed_recorder("suppressed_exception", exc)
    except recoverable_exceptions as record_exc:
        _ = record_exc


def parse_result_message(
    message: object,
    *,
    log_error: Callable[[str], object],
) -> InMemoryResultMessageParts | None:
    message_items = no_hook_sequence_items(message)
    item_count = len(message_items)
    if item_count >= 7:
        _kind, job_id, path, result, pid, timestamp, attempt = message_items[:7]
    elif item_count == 6:
        _kind, job_id, path, result, pid, timestamp = message_items
        attempt = 0
    else:
        log_error(bad_result_message_text(message, item_count))
        return None
    return InMemoryResultMessageParts(
        job_id=job_id,
        path=path,
        result=result,
        pid=pid,
        timestamp=timestamp,
        attempt=attempt,
    )


def resolve_terminal_record(
    *,
    job_records: MutableMapping[int, MutableMapping[str, object]],
    terminal: MutableSet[int],
    parts: InMemoryResultMessageParts,
) -> tuple[int, int, dict[str, object]] | None:
    safe_job_id, job_id_reason = scheduler_int(
        parts.job_id,
        default=0,
        minimum=0,
        reason="inmemory_result_job_id_rejected",
    )
    safe_attempt, attempt_reason = scheduler_int(
        parts.attempt,
        default=0,
        minimum=0,
        reason="inmemory_result_attempt_rejected",
    )
    if job_id_reason or attempt_reason or type(job_records) is not dict:
        return None
    record = exact_record(dict.get(job_records, safe_job_id))
    record_attempt, record_attempt_reason = scheduler_int(
        dict.get(record or {}, "attempt", 0),
        default=0,
        minimum=0,
        reason="inmemory_result_record_attempt_rejected",
    )
    if record is None or record_attempt_reason or safe_job_id in terminal:
        return None
    if record_attempt != safe_attempt:
        return None
    return safe_job_id, safe_attempt, record


def apply_terminal_state(
    *,
    recovery: object,
    record: dict[str, object],
    safe_job_id: int,
    safe_attempt: int,
    terminal_state: str,
    pid: object,
    completion_time: float,
) -> None:
    record_lifecycle_request, lifecycle_reason = safe_scheduler_bound_method(
        recovery,
        "record_lifecycle_request",
        reason_prefix="unsafe_inmemory_recovery",
    )
    if record_lifecycle_request is not None and not lifecycle_reason:
        record_lifecycle_request(
            InMemoryLifecycleRecordRequest(
                job_id=safe_job_id,
                attempt=safe_attempt,
                transition=terminal_state,
                worker_pid=pid,
                state=terminal_state,
            )
        )
    elif lifecycle_reason:
        record["record_lifecycle_request_unavailable"] = lifecycle_reason
    terminal_transition, transition_reason = safe_scheduler_bound_method(
        recovery,
        "terminal_transition",
        reason_prefix="unsafe_inmemory_recovery",
    )
    if terminal_transition is not None and not transition_reason:
        terminal_transition(record, state=terminal_state, attempt=safe_attempt, now=completion_time)
        return
    record["state"] = terminal_state
    record["completed_at"] = completion_time
    if transition_reason:
        record["terminal_transition_unavailable"] = transition_reason


def observe_completed_result_cost(
    *,
    record: dict[str, object],
    record_attempt: int,
    path: object,
    record_stage_cost_observation: Callable[..., object],
    wall_time: Callable[[], float],
) -> None:
    now = wall_time()
    start_time, _start_reason = record_start_time(record, default=now)
    rss_mb, _rss_reason = scheduler_float(
        dict.get(record, "worker_rss_mb", 0.0),
        default=0.0,
        reason="inmemory_result_worker_rss_mb_rejected",
    )
    stalled, _stalled_reason = scheduler_bool(
        dict.get(record, "cancel_requested_at"),
        default=False,
        reason="inmemory_result_cancel_requested_rejected",
    )
    record_stage_cost_observation(
        path=path,
        cost=dict.get(record, "cost"),
        duration_sec=now - start_time,
        rss_mb=rss_mb,
        stalled=stalled,
        retried=record_attempt > 0,
    )


def sleep_for_throttle(
    *,
    throttle_sec: float,
    sleep: Callable[[float], object],
) -> bool:
    throttle_value, throttle_reason = scheduler_float(
        throttle_sec,
        default=0.0,
        reason="inmemory_result_throttle_rejected",
    )
    if throttle_reason:
        throttle_value = 0.0
    if throttle_value <= 0.0:
        return False
    sleep(max(0.0, throttle_value))
    return True
