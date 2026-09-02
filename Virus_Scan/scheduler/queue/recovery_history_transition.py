"""Immutable recovery-history transition request ownership."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeAlias

from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text
from Virus_Scan.scheduler.queue.recovery_contract_support import (
    bounded_history_with_item as _bounded_history_with_item,
    record_snapshot as _record_snapshot,
    recovery_integer_result as _int_result,
    recovery_timestamp,
    transition_mapping as _transition_mapping,
)

SchedulerRecord: TypeAlias = Mapping[str, object]
SchedulerMutableRecord: TypeAlias = dict[str, object]


@dataclass(frozen=True, slots=True)
class RecoveryHistoryTransition:
    record: SchedulerRecord
    item: SchedulerRecord

    def __post_init__(self) -> None:
        object.__setattr__(self, "record", _transition_mapping(self.record))
        object.__setattr__(self, "item", _transition_mapping(self.item))

    def as_record(self) -> SchedulerMutableRecord:
        return materialize_scheduler_mapping(self.record)

    def as_item(self) -> SchedulerMutableRecord:
        return materialize_scheduler_mapping(self.item)


@dataclass(frozen=True, slots=True)
class RecoveryHistoryTransitionRequest:
    """Internal request for one immutable recovery-history transition."""

    record: SchedulerRecord
    reason: object
    pid: object | None = None
    attempt: object | None = None
    now: float | None = None
    action: str = "retry"
    extra: SchedulerRecord | None = None


def build_recovery_history_transition(
    request: RecoveryHistoryTransitionRequest,
) -> RecoveryHistoryTransition:
    """Return immutable recovery-history output without mutating scheduler state."""
    source = _record_snapshot(request.record)
    ts, iso = recovery_timestamp(request.now)
    item = {
        "action": scheduler_evidence_text(
            request.action,
            missing_text="missing_recovery_action",
            field_name="recovery_action",
        ),
        "reason": scheduler_evidence_text(
            request.reason,
            missing_text="missing_recovery_reason",
            field_name="recovery_reason",
        ),
        "pid": request.pid,
        "time": ts,
        "iso": iso,
        "attempt": 0,
    }
    attempt_value, attempt_issue = _int_result(
        request.attempt if request.attempt is not None else source.get("attempt"),
        replacement=0,
        field_name="recovery_attempt",
    )
    item["attempt"] = attempt_value
    if attempt_issue is not None:
        item["attempt_issue"] = attempt_issue
    if request.extra is not None:
        item.update(_record_snapshot(request.extra))
    updated = dict(source)
    updated["history"] = _bounded_history_with_item(source, item)
    return RecoveryHistoryTransition(
        MappingProxyType(updated),
        MappingProxyType(item),
    )
