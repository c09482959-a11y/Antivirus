"""No-hook lifecycle transition contracts for in-memory scheduler replay."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_float,
    scheduler_int,
    scheduler_text,
    scheduler_value_snapshot,
)
from Virus_Scan.scheduler.queue.inmemory_lifecycle_reasons import lifecycle_rejection_reason


@dataclass(frozen=True, order=True)
class InMemoryLifecycleTransition:
    """Canonical scheduler lifecycle transition."""

    epoch: int
    sequence: int
    job_id: int
    attempt: int
    transition: str
    monotonic_ns: int
    timestamp: float
    worker_pid: int = 0
    reason: str = ""
    state: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "epoch": self.epoch, "sequence": self.sequence, "job_id": self.job_id,
            "attempt": self.attempt, "transition": self.transition,
            "monotonic_ns": self.monotonic_ns, "timestamp": self.timestamp,
            "worker_pid": self.worker_pid, "reason": self.reason, "state": self.state,
        }



def lifecycle_text(value: object, default: str = "", *, reason: str = "lifecycle_text_rejected") -> tuple[str, str]:
    if value is None:
        return default, ""
    text, text_reason = scheduler_text(value, replacement_text=default, unsupported_reason=reason)
    if text_reason:
        return default, text_reason
    return text, ""



def lifecycle_replay_rejection(*, item: object, field: str, value: object, reason: str) -> dict[str, object]:
    return {
        "lifecycle_replay_rejected": True,
        "field": field,
        "reason": reason,
        "value_type": no_hook_type_name(value),
        "value": scheduler_value_snapshot(value, field_name=field),
        "item_type": no_hook_type_name(item),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }


def lifecycle_transition_snapshot(item: object) -> tuple[dict[str, object] | None, tuple[dict[str, object], ...]]:
    if isinstance(item, InMemoryLifecycleTransition):
        return item.to_dict(), ()
    if no_hook_mapping_items(item) is None:
        return None, (
            lifecycle_replay_rejection(
                item=item,
                field="transition_record",
                value=item,
                reason="lifecycle_transition_mapping_rejected",
            ),
        )

    rejections: list[dict[str, object]] = []
    epoch = _required_int(item, "epoch", 0, rejections)
    sequence = _required_int(item, "sequence", 0, rejections)
    job_id = _required_int(item, "job_id", -1, rejections)
    attempt = _required_int(item, "attempt", 0, rejections)
    transition = _required_text(item, "transition", "", rejections)
    monotonic_ns, monotonic_reason = scheduler_int(
        scheduler_mapping_value(item, "monotonic_ns"),
        default=0,
        reason="lifecycle_monotonic_ns_rejected",
    )
    timestamp, timestamp_reason = scheduler_float(
        scheduler_mapping_value(item, "timestamp"),
        default=0.0,
        reason="lifecycle_timestamp_rejected",
    )
    worker_pid, worker_reason = scheduler_int(
        scheduler_mapping_value(item, "worker_pid"),
        default=0,
        reason="lifecycle_worker_pid_rejected",
    )
    reason_text, _reason_reason = lifecycle_text(
        scheduler_mapping_value(item, "reason"),
        "",
        reason="lifecycle_reason_rejected",
    )
    state_text, _state_reason = lifecycle_text(
        scheduler_mapping_value(item, "state"),
        "",
        reason="lifecycle_state_rejected",
    )
    for field, raw, parse_reason in (
        ("monotonic_ns", scheduler_mapping_value(item, "monotonic_ns"), monotonic_reason),
        ("timestamp", scheduler_mapping_value(item, "timestamp"), timestamp_reason),
        ("worker_pid", scheduler_mapping_value(item, "worker_pid"), worker_reason),
    ):
        if parse_reason and raw is not None:
            rejections.append(lifecycle_replay_rejection(item=item, field=field, value=raw, reason=parse_reason))
    if job_id < 0 and not rejections:
        rejections.append(
            lifecycle_replay_rejection(
                item=item,
                field="job_id",
                value=scheduler_mapping_value(item, "job_id"),
                reason="lifecycle_job_id_rejected",
            )
        )
    return {
        "epoch": epoch,
        "sequence": sequence,
        "job_id": job_id,
        "attempt": attempt,
        "transition": transition,
        "monotonic_ns": monotonic_ns,
        "timestamp": timestamp,
        "worker_pid": worker_pid,
        "reason": reason_text,
        "state": state_text,
    }, tuple(rejections)


def lifecycle_transition_key(item: object) -> tuple[int, int, int, int, str]:
    transition, _rejections = lifecycle_transition_snapshot(item)
    if transition is None:
        return (0, 0, -1, 0, "")
    epoch, _epoch_reason = scheduler_int(dict.get(transition, "epoch"), default=0, reason="lifecycle_epoch_rejected")
    sequence, _sequence_reason = scheduler_int(dict.get(transition, "sequence"), default=0, reason="lifecycle_sequence_rejected")
    job_id, _job_id_reason = scheduler_int(dict.get(transition, "job_id"), default=-1, reason="lifecycle_job_id_rejected")
    attempt, _attempt_reason = scheduler_int(dict.get(transition, "attempt"), default=0, reason="lifecycle_attempt_rejected")
    transition_text, _transition_reason = lifecycle_text(dict.get(transition, "transition"), "", reason="lifecycle_transition_rejected")
    return (
        epoch,
        sequence,
        job_id,
        attempt,
        transition_text,
    )


def _required_int(item: object, field: str, default: int, rejections: list[dict[str, object]]) -> int:
    raw = scheduler_mapping_value(item, field)
    parsed, reason = scheduler_int(raw, default=default, reason=lifecycle_rejection_reason(field))
    if reason:
        rejections.append(lifecycle_replay_rejection(item=item, field=field, value=raw, reason=reason))
    return parsed


def _required_text(item: object, field: str, default: str, rejections: list[dict[str, object]]) -> str:
    raw = scheduler_mapping_value(item, field)
    parsed, reason = lifecycle_text(raw, default, reason=lifecycle_rejection_reason(field))
    if reason:
        rejections.append(lifecycle_replay_rejection(item=item, field=field, value=raw, reason=reason))
    return parsed


__all__ = (
    "InMemoryLifecycleTransition",
    "lifecycle_rejection_reason",
    "lifecycle_text",
    "lifecycle_transition_key",
    "lifecycle_transition_snapshot",
)
