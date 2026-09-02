"""Canonical scheduler recovery/retry transition helpers."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Mapping
from typing import TypeAlias

from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text
from Virus_Scan.scheduler.queue.recovery_contract_support import (
    record_snapshot as _record_snapshot,
    recovery_integer_result as _int_result,
    recovery_timestamp,
    transition_mapping as _transition_mapping,
)
from Virus_Scan.scheduler.queue.recovery_history_transition import (
    RecoveryHistoryTransition,
    RecoveryHistoryTransitionRequest,
    build_recovery_history_transition,
)

SchedulerRecord: TypeAlias = Mapping[str, object]
SchedulerMutableRecord: TypeAlias = dict[str, object]

RECOVERY_FLAGS = 0x02 | 0x04  # HB_CANCEL_REQUEST | HB_POISONED; kept local to avoid circular imports.

_LIVE_RUNTIME_KEYS = (
    "pid", "worker_pid", "claimed_by", "active_claim", "heartbeat_time",
    "started_at", "queued_at", "queued_timeout_armed_at", "progress_time",
)
_QUEUE_INFO_LIVE_KEYS = (
    "claimed_time", "heartbeat_time", "progress_time", "owner_pid",
    "worker_pid", "worker_id", "claim_path", "active_path",
    "progress_marker", "cancel_requested", "poisoned", "stalled",
)


@dataclass(frozen=True, slots=True)
class InMemoryRetryTransition:
    old_generation: int
    new_generation: int
    record: SchedulerRecord

    def __post_init__(self) -> None:
        object.__setattr__(self, "record", _transition_mapping(self.record))

    def as_record(self) -> SchedulerMutableRecord:
        return materialize_scheduler_mapping(self.record)



def retry_already_pending(record: SchedulerRecord | None) -> bool:
    if record is None:
        return False
    source = _record_snapshot(record)
    state = scheduler_evidence_text(source.get("state"), missing_text="missing_retry_state", field_name="retry_state")
    attempt, _attempt_issue = _int_result(source.get("attempt"), replacement=0, field_name="retry_attempt")
    active = source.get("retry_pending_active") is True
    if state == "pending_retry":
        return active and source.get("retry_pending_generation") == attempt
    return bool(source.get("retry_pending_generation") == attempt and active)


def build_inmemory_retry_transition(record: SchedulerRecord, reason: object, *, pid: object | None = None, now: float | None = None) -> InMemoryRetryTransition:
    """Return immutable in-memory retry transition output for caller-owned state replacement."""
    source = _record_snapshot(record)
    old_generation, attempt_issue = _int_result(source.get("attempt"), replacement=0, field_name="retry_attempt")
    new_generation = old_generation + 1
    history_transition = build_recovery_history_transition(
        RecoveryHistoryTransitionRequest(
            record=source,
            reason=reason,
            pid=pid,
            attempt=source.get("attempt"),
            now=now,
            action="retry",
        )
    )
    updated = dict(history_transition.record)
    for key in _LIVE_RUNTIME_KEYS:
        if key in ("queued_at", "queued_timeout_armed_at", "started_at"):
            updated[key] = 0.0
        else:
            updated.pop(key, None)
    ts, iso = recovery_timestamp(now)
    updated.update({
        "attempt": new_generation,
        "generation": new_generation,
        "state": "pending_retry",
        "retry_pending_generation": new_generation,
        "retry_pending_active": True,
        "retry_pending_reason": scheduler_evidence_text(
            reason,
            missing_text="missing_retry_reason",
            field_name="retry_reason",
        ),
        "retry_pending_time": ts,
        "retry_pending_iso": iso,
    })
    if attempt_issue is not None:
        updated["attempt_issue"] = attempt_issue
    return InMemoryRetryTransition(old_generation, new_generation, MappingProxyType(updated))


def build_recovery_duplicate_ignored_transition(record: SchedulerRecord, reason: object, *, pid: object | None = None, now: float | None = None) -> RecoveryHistoryTransition:
    """Return immutable duplicate-recovery evidence without mutating caller-owned state."""
    return build_recovery_history_transition(
        RecoveryHistoryTransitionRequest(
            record=record,
            reason=reason,
            pid=pid,
            attempt=_record_snapshot(record).get("attempt", 0),
            now=now,
            action="duplicate_recovery_ignored",
        )
    )


def cancel_payload(reason: object, generation: object, *, now: float | None = None) -> SchedulerMutableRecord:
    ts, iso = recovery_timestamp(now)
    generation_value, generation_issue = _int_result(generation, replacement=0, field_name="recovery_generation")
    payload = {
        "generation": generation_value,
        "flags": RECOVERY_FLAGS,
        "reason": scheduler_evidence_text(reason, missing_text="missing_recovery_reason", field_name="recovery_reason"),
        "time": ts,
        "iso": iso,
    }
    if generation_issue is not None:
        payload["generation_issue"] = generation_issue
    return payload


def reset_queue_retry_runtime_metadata(job: SchedulerRecord | None, *, now: float | None = None, reason: object = "reclaim") -> SchedulerMutableRecord:
    """Return a job copy safe to publish back to pending/ after reclaim."""
    out = _record_snapshot(job)
    ts, iso = recovery_timestamp(now)
    qi = _record_snapshot(out.get("queue_info"))
    for key in _QUEUE_INFO_LIVE_KEYS:
        qi.pop(key, None)
    retry_generation, retry_generation_issue = _int_result(
        qi.get("retry_generation"),
        replacement=0,
        field_name="retry_generation",
    )
    qi.update({
        "retry_pending_time": ts,
        "retry_pending_iso": iso,
        "retry_pending_reason": scheduler_evidence_text(
            reason,
            missing_text="missing_recovery_reason",
            field_name="recovery_reason",
        ),
        "retry_generation": retry_generation + 1,
        "retry_pending_active": True,
    })
    if retry_generation_issue is not None:
        qi["retry_generation_issue"] = retry_generation_issue
    out["queue_info"] = qi
    for key in ("claimed_by", "active_claim", "heartbeat_time", "worker_pid"):
        out.pop(key, None)
    return out
