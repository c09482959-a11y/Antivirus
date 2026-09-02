"""Replayable retry and recovery boundary decisions."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_items_from_items
from dataclasses import dataclass, field as dataclass_field
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.immutable_outputs import (
    immutable_mapping,
    materialize_scheduler_mapping,
)
from Virus_Scan.scheduler.queue.retry_integrity_decisions import (
    RetryIntegrityMappingDecision,
    RetryIntegrityMissingDecision,
    retry_integrity_mapping_decision,
    retry_integrity_missing_decision,
)
from Virus_Scan.scheduler.queue.retry_reason_support import retry_field_name, retry_reason


@dataclass(frozen=True, slots=True)
class SchedulerRecoveryRecordDecision:
    accepted: bool
    reason: str
    value_type: str
    items: tuple[tuple[str, object], ...] = ()
    evidence: Mapping[str, object] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        object.__setattr__(self, "evidence", immutable_mapping(self.evidence))

    def as_mapping(self) -> dict[str, object]:
        if not self.accepted:
            return {}
        return dict(self.items)


@dataclass(frozen=True, slots=True)
class SchedulerRecoveryTextDecision:
    accepted: bool
    text: str
    reason: str
    value_type: str

    def as_text(self) -> str:
        return self.text if self.accepted else ""


@dataclass(frozen=True, slots=True)
class RetryOptionalIntDecision:
    accepted: bool
    value: int | None
    reason: str
    field_name: str
    value_type: str

    def as_optional_int(self) -> int | None:
        if self.accepted:
            return self.value
        if self.reason.endswith("_missing_optional_int"):
            return None
        raise ValueError(self.reason)


@dataclass(frozen=True, slots=True)
class RetryHistorySnapshotDecision:
    accepted: bool
    reason: str
    value_type: str
    entries: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))

    def as_history(self) -> tuple[object, ...]:
        return self.entries


def scheduler_recovery_record_decision(value: Mapping[str, object] | None) -> SchedulerRecoveryRecordDecision:
    materialized = materialize_scheduler_mapping(immutable_mapping(value))
    if type(materialized) is dict and dict.get(materialized, "scheduler_mapping_unavailable") is not True:
        return SchedulerRecoveryRecordDecision(
            accepted=True,
            reason="scheduler_recovery_record_accepted",
            value_type=no_hook_type_name(value),
            items=scheduler_str_key_items_from_items(dict.items(materialized)),
        )
    reason = "scheduler_recovery_record_missing" if value is None else "scheduler_recovery_record_unavailable"
    evidence = materialized if type(materialized) is dict else {"scheduler_mapping_unavailable": True}
    return SchedulerRecoveryRecordDecision(accepted=False, reason=reason, value_type=no_hook_type_name(value), evidence=evidence)


def scheduler_recovery_text_decision(value: object) -> SchedulerRecoveryTextDecision:
    text, reason = no_hook_text(value, unsupported_reason="scheduler_recovery_text_rejected")
    if reason == "" and text.strip():
        return SchedulerRecoveryTextDecision(accepted=True, text=text, reason="scheduler_recovery_text_accepted", value_type=no_hook_type_name(value))
    return SchedulerRecoveryTextDecision(
        accepted=False,
        text="",
        reason=reason or "scheduler_recovery_text_missing",
        value_type=no_hook_type_name(value),
    )


def retry_optional_int_decision(value: object, *, field_name: object) -> RetryOptionalIntDecision:
    retry_field = retry_field_name(field_name)
    if value is None:
        return RetryOptionalIntDecision(accepted=False, value=None, reason=retry_reason(field_name, "missing_optional_int"), field_name=retry_field, value_type="NoneType")
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        reason=retry_reason(field_name, "rejected"),
        non_finite_reason=retry_reason(field_name, "non_finite"),
    )
    if reason:
        return RetryOptionalIntDecision(accepted=False, value=None, reason=reason, field_name=retry_field, value_type=no_hook_type_name(value))
    return RetryOptionalIntDecision(accepted=True, value=parsed, reason=retry_reason(field_name, "accepted"), field_name=retry_field, value_type=no_hook_type_name(value))


def retry_history_decision(value: object) -> RetryHistorySnapshotDecision:
    if value is None:
        return RetryHistorySnapshotDecision(accepted=False, reason="retry_history_missing", value_type="NoneType")
    if type(value) is list:
        return RetryHistorySnapshotDecision(accepted=True, reason="retry_history_list", value_type="list", entries=tuple(value))
    if type(value) is tuple:
        return RetryHistorySnapshotDecision(accepted=True, reason="retry_history_tuple", value_type="tuple", entries=value)
    value_type = no_hook_type_name(value)
    return RetryHistorySnapshotDecision(
        accepted=False,
        reason="retry_history_rejected",
        value_type=value_type,
        entries=({
            "reason": "retry_history_rejected",
            "action": "retry_history_rejected",
            "value_type": value_type,
            "queue_failure": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_reproduce": True,
        },),
    )



__all__ = (
    "RetryHistorySnapshotDecision",
    "RetryIntegrityMappingDecision",
    "RetryIntegrityMissingDecision",
    "RetryOptionalIntDecision",
    "SchedulerRecoveryRecordDecision",
    "SchedulerRecoveryTextDecision",
    "retry_history_decision",
    "retry_integrity_mapping_decision",
    "retry_integrity_missing_decision",
    "retry_optional_int_decision",
    "scheduler_recovery_record_decision",
    "scheduler_recovery_text_decision",
)
