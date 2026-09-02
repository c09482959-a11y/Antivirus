"""Bounded result-completion state transitions for in-memory workers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, MutableMapping, MutableSet

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.queue.inmemory_result_completion_projection import result_queue_failure
from Virus_Scan.scheduler.queue.inmemory_result_completion_state import (
    apply_terminal_state,
    observe_completed_result_cost,
    parse_result_message,
    record_suppressed_exception,
    resolve_terminal_record,
)


@dataclass(frozen=True, slots=True)
class InMemoryCompletionContext:
    parts: object
    safe_job_id: int
    safe_attempt: int
    record: MutableMapping[str, object]


@dataclass(frozen=True, slots=True)
class InMemoryCompletionStateResult:
    terminal_failed: bool


def resolve_completion_context(
    *,
    message: object,
    job_records: MutableMapping[int, MutableMapping[str, object]],
    terminal: MutableSet[int],
    log_error: Callable[[str], object],
) -> InMemoryCompletionContext | None:
    """Resolve a result message into its live terminal record."""
    parts = parse_result_message(message, log_error=log_error)
    if parts is None:
        return None
    terminal_record = resolve_terminal_record(
        job_records=job_records,
        terminal=terminal,
        parts=parts,
    )
    if terminal_record is None:
        return None
    safe_job_id, safe_attempt, record = terminal_record
    return InMemoryCompletionContext(parts, safe_job_id, safe_attempt, record)


def apply_completion_terminal_state(
    *,
    context: InMemoryCompletionContext,
    active: MutableMapping[int, object],
    terminal: MutableSet[int],
    failed: MutableSet[int],
    done: MutableSet[int],
    recovery: object,
    state_index: object,
    wall_time: Callable[[], float],
) -> InMemoryCompletionStateResult:
    """Move a completed result into the terminal in-memory state."""
    parts = context.parts
    record = context.record
    safe_job_id = context.safe_job_id
    safe_attempt = context.safe_attempt
    active.pop(safe_job_id, None)
    terminal.add(safe_job_id)
    terminal_failed = result_queue_failure(parts.result)
    terminal_state = "failed" if terminal_failed else "done"
    completion_time, timestamp_reason = scheduler_float(
        parts.timestamp,
        default=wall_time(),
        reason="inmemory_result_timestamp_rejected",
    )
    if timestamp_reason:
        record["completion_timestamp_rejected"] = timestamp_reason
    apply_terminal_state(
        recovery=recovery,
        record=record,
        safe_job_id=safe_job_id,
        safe_attempt=safe_attempt,
        terminal_state=terminal_state,
        pid=parts.pid,
        completion_time=completion_time,
    )
    state_index.sync_record(safe_job_id, record, due_at=None)
    if terminal_failed:
        failed.add(safe_job_id)
    else:
        done.add(safe_job_id)
    return InMemoryCompletionStateResult(terminal_failed)


def observe_completion_cost_safely(
    *,
    context: InMemoryCompletionContext,
    record_stage_cost_observation: Callable[..., object],
    wall_time: Callable[[], float],
    recoverable_exceptions: tuple[type[BaseException], ...],
    suppressed_recorder: Callable[[str, BaseException], object],
) -> None:
    """Record completed-result cost while preserving suppressed evidence."""
    try:
        observe_completed_result_cost(
            record=context.record,
            record_attempt=context.safe_attempt,
            path=context.parts.path,
            record_stage_cost_observation=record_stage_cost_observation,
            wall_time=wall_time,
        )
    except recoverable_exceptions as exc:
        record_suppressed_exception(
            suppressed_recorder,
            recoverable_exceptions,
            exc,
        )


__all__ = (
    "InMemoryCompletionContext",
    "InMemoryCompletionStateResult",
    "apply_completion_terminal_state",
    "observe_completion_cost_safely",
    "resolve_completion_context",
)
