"""Deterministic in-memory scheduler lifecycle helpers."""
from __future__ import annotations

from typing import Iterable
import time

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int
from Virus_Scan.scheduler.queue.inmemory_lifecycle_contracts import (
    InMemoryLifecycleTransition,
    lifecycle_text,
    lifecycle_transition_key as canonical_transition_key,
    lifecycle_transition_snapshot,
)
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import (
    InMemoryLifecycleMutationDecision,
    generation_current_decision,
    mark_retry_admitted_decision,
    terminal_transition_decision,
)

TERMINAL_STATES = frozenset({"done", "failed", "cancelled", "quarantined"})
LIVE_STATES = frozenset({"queued", "assigned", "running"})


def make_transition(
    *,
    epoch: int,
    sequence: int,
    job_id: int,
    attempt: int,
    transition: str,
    worker_pid: object = 0,
    reason: object = "",
    state: object = "",
    timestamp: float | None = None,
    monotonic_ns: int | None = None,
) -> InMemoryLifecycleTransition:
    epoch_value, _epoch_reason = scheduler_int(epoch, default=0, reason="lifecycle_epoch_rejected")
    sequence_value, _sequence_reason = scheduler_int(sequence, default=0, reason="lifecycle_sequence_rejected")
    job_id_value, _job_reason = scheduler_int(job_id, default=-1, reason="lifecycle_job_id_rejected")
    attempt_value, _attempt_reason = scheduler_int(attempt, default=0, reason="lifecycle_attempt_rejected")
    transition_value, _transition_reason = lifecycle_text(
        transition,
        "unknown",
        reason="lifecycle_transition_rejected",
    )
    worker_pid_value, _worker_reason = scheduler_int(
        worker_pid,
        default=0,
        reason="lifecycle_worker_pid_rejected",
    )
    reason_value, _reason_reason = lifecycle_text(reason, "", reason="lifecycle_reason_rejected")
    state_value, _state_reason = lifecycle_text(state, "", reason="lifecycle_state_rejected")
    monotonic_value, _monotonic_reason = scheduler_int(
        monotonic_ns if monotonic_ns is not None else time.monotonic_ns(),
        default=0,
        reason="lifecycle_monotonic_ns_rejected",
    )
    timestamp_value, _timestamp_reason = scheduler_float(
        timestamp if timestamp is not None else time.time(),
        default=0.0,
        reason="lifecycle_timestamp_rejected",
    )
    return InMemoryLifecycleTransition(
        epoch=epoch_value,
        sequence=sequence_value,
        job_id=job_id_value,
        attempt=attempt_value,
        transition=transition_value,
        monotonic_ns=monotonic_value,
        timestamp=timestamp_value,
        worker_pid=worker_pid_value,
        reason=reason_value,
        state=state_value,
    )


def replay_lifecycle(transitions: Iterable[object]) -> dict[int, dict[str, object]]:
    """Reconstruct lifecycle state deterministically from transition records."""
    state: dict[int, dict[str, object]] = {}
    for item in sorted(transitions, key=canonical_transition_key):
        d, rejections = lifecycle_transition_snapshot(item)
        if d is None or rejections:
            rec = state.setdefault(-1, {"job_id": -1, "attempt": 0, "state": "lifecycle_replay_rejected", "history": ()})
            existing = tuple(dict.get(rec, "lifecycle_replay_rejections") or ())
            rec["lifecycle_replay_rejections"] = existing + rejections
            rec["history"] = tuple(list(dict.get(rec, "history") or ())[-63:] + list(rejections))
            if d is None:
                continue
            rejected_job_id, _rejected_job_reason = scheduler_int(dict.get(d, "job_id"), default=-1, reason="lifecycle_job_id_rejected")
            if rejected_job_id < 0:
                continue
        job_id, _job_reason = scheduler_int(dict.get(d, "job_id"), default=-1, reason="lifecycle_job_id_rejected")
        attempt, _attempt_reason = scheduler_int(dict.get(d, "attempt"), default=0, reason="lifecycle_attempt_rejected")
        trans, _transition_reason = lifecycle_text(dict.get(d, "transition"), "", reason="lifecycle_transition_rejected")
        if job_id not in state:
            state[job_id] = {"job_id": job_id, "attempt": attempt, "state": "pending", "history": ()}
        rec = state[job_id]
        current_attempt, _current_reason = scheduler_int(
            dict.get(rec, "attempt"),
            default=0,
            reason="lifecycle_attempt_rejected",
        )
        if attempt < current_attempt:
            ignored = tuple(dict.get(rec, "ignored") or ())
            rec["ignored"] = (*ignored, {'transition': trans, 'attempt': attempt, 'reason': 'stale_generation'})
            continue
        if attempt > current_attempt:
            rec.update({"attempt": attempt, "state": "pending"})
        if trans in LIVE_STATES:
            rec["state"] = trans
            rec["retry_pending_active"] = False
        elif trans == "retry_pending":
            if dict.get(rec, "state") not in TERMINAL_STATES:
                rec["attempt"] = attempt
                rec["state"] = "pending_retry"
                rec["retry_pending_active"] = True
        elif trans in TERMINAL_STATES:
            rec["state"] = trans
            rec["retry_pending_active"] = False
            rec["terminal"] = True
        elif trans == "heartbeat":
            if dict.get(rec, "state") not in TERMINAL_STATES:
                rec["last_heartbeat"] = dict.get(d, "timestamp")
        rec["last_sequence"] = dict.get(d, "sequence")
        rec["history"] = tuple([*list(dict.get(rec, 'history') or ())[-63:], d])
    return state


__all__ = (
    "LIVE_STATES",
    "TERMINAL_STATES",
    "InMemoryLifecycleMutationDecision",
    "InMemoryLifecycleTransition",
    "canonical_transition_key",
    "generation_current_decision",
    "make_transition",
    "mark_retry_admitted_decision",
    "replay_lifecycle",
    "terminal_transition_decision",
)
