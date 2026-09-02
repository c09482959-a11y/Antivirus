"""Typed in-memory lifecycle mutation decisions."""
from __future__ import annotations

from dataclasses import dataclass
import time

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int
from Virus_Scan.scheduler.queue.inmemory_lifecycle_contracts import lifecycle_text


@dataclass(frozen=True)
class InMemoryLifecycleMutationDecision:
    """Replayable boolean lifecycle mutation decision."""

    accepted: bool
    reason: str
    field: str = ""
    transition: str = ""
    changed: bool = False


def generation_current_decision(record: object, *, attempt: object) -> InMemoryLifecycleMutationDecision:
    current, current_reason = scheduler_int(
        scheduler_mapping_value(record, "attempt"),
        default=0,
        reason="lifecycle_attempt_rejected",
    )
    requested, requested_reason = scheduler_int(attempt, default=-1, reason="lifecycle_attempt_rejected")
    if current_reason:
        return InMemoryLifecycleMutationDecision(accepted=False, reason=current_reason, field="record.attempt", transition="generation_current")
    if requested_reason:
        return InMemoryLifecycleMutationDecision(accepted=False, reason=requested_reason, field="attempt", transition="generation_current")
    if current != requested:
        return InMemoryLifecycleMutationDecision(accepted=False, reason="lifecycle_generation_mismatch", field="attempt", transition="generation_current")
    return InMemoryLifecycleMutationDecision(accepted=True, reason="", field="attempt", transition="generation_current")


def mark_retry_admitted_decision(
    record: dict[str, object],
    *,
    attempt: object,
    now: float | None = None,
) -> InMemoryLifecycleMutationDecision:
    """Clear pending-retry state once a generation is admitted and return replayable evidence."""
    if type(record) is not dict:
        return InMemoryLifecycleMutationDecision(accepted=False, reason="lifecycle_record_rejected", field="record", transition="retry_admitted")
    generation = generation_current_decision(record, attempt=attempt)
    if not generation.accepted:
        return InMemoryLifecycleMutationDecision(accepted=False, reason=generation.reason, field=generation.field, transition="retry_admitted")
    admitted, _admitted_reason = scheduler_int(attempt, default=-1, reason="lifecycle_attempt_rejected")
    state, _state_reason = lifecycle_text(dict.get(record, "state"), "", reason="lifecycle_state_rejected")
    if dict.get(record, "retry_pending_active") or state == "pending_retry":
        record["retry_pending_active"] = False
        record["retry_admitted_generation"] = admitted
        admitted_time, _time_reason = scheduler_float(
            now if now is not None else time.time(),
            default=0.0,
            reason="lifecycle_retry_admitted_time_rejected",
        )
        record["retry_admitted_time"] = admitted_time
        existing_history = dict.get(record, "history")
        history_items: tuple[object, ...]
        if type(existing_history) is list:
            history_items = tuple(existing_history)
        elif type(existing_history) is tuple:
            history_items = existing_history
        else:
            history_items = ()
        admitted_item = {"reason": "retry_generation_admitted", "attempt": admitted, "time": admitted_time}
        record["history"] = history_items[-63:] + (admitted_item,)
        return InMemoryLifecycleMutationDecision(accepted=True, reason="retry_generation_admitted", field="attempt", transition="retry_admitted", changed=True)
    return InMemoryLifecycleMutationDecision(accepted=True, reason="retry_generation_already_current", field="attempt", transition="retry_admitted")


def terminal_transition_decision(
    record: dict[str, object],
    *,
    state: str,
    attempt: object,
    now: float | None = None,
) -> InMemoryLifecycleMutationDecision:
    if type(record) is not dict:
        return InMemoryLifecycleMutationDecision(accepted=False, reason="lifecycle_record_rejected", field="record", transition="terminal_transition")
    generation = generation_current_decision(record, attempt=attempt)
    if not generation.accepted:
        return InMemoryLifecycleMutationDecision(accepted=False, reason=generation.reason, field=generation.field, transition="terminal_transition")
    state_value, state_reason = lifecycle_text(state, "done", reason="lifecycle_state_rejected")
    if state_reason:
        return InMemoryLifecycleMutationDecision(accepted=False, reason=state_reason, field="state", transition="terminal_transition")
    terminal_time, _time_reason = scheduler_float(
        now if now is not None else time.time(),
        default=0.0,
        reason="lifecycle_terminal_time_rejected",
    )
    record["retry_pending_active"] = False
    record["state"] = state_value
    record["terminal_time"] = terminal_time
    return InMemoryLifecycleMutationDecision(accepted=True, reason="terminal_transition_applied", field="state", transition="terminal_transition", changed=True)


__all__ = (
    "InMemoryLifecycleMutationDecision",
    "generation_current_decision",
    "mark_retry_admitted_decision",
    "terminal_transition_decision",
)
