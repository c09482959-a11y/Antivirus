"""Replayable decisions for process-queue stale recovery projections."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_items_from_items
from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float


@dataclass(frozen=True, slots=True)
class StaleOptionalFloatDecision:
    """Typed decision for optional stale-recovery float projection."""

    value: float | None
    reason: str
    value_type: str

    def as_optional_float(self) -> float | None:
        """Return the optional-float projection for callers."""
        return self.value


@dataclass(frozen=True, slots=True)
class StaleRecoveredRecordDecision:
    """Typed decision for stale-recovery record materialization."""

    accepted: bool
    reason: str
    value_type: str
    record: tuple[tuple[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "record", tuple(self.record))

    def as_record(self) -> dict[str, object]:
        """Return the recovered-record mapping for callers."""
        if self.accepted:
            return dict(self.record)
        if self.reason == "stale_recovered_record_missing":
            return {}
        return {
            "recovery_failed": 1,
            "recovered_unavailable": {
                "unsupported_scheduler_value": True,
                "status": "failed",
                "failed": True,
                "stage": "scheduler_json_materialization",
                "state": "failed",
                "error_category": "scheduler_json_materialization_unsupported",
                "error_source": "scheduler.queue.process_queue_stale_recovery",
                "message": "unsupported stale recovery record cannot be materialized without caller hooks",
                "field_name": "process_queue_recovered",
                "value_type": self.value_type,
                "context": {"unsupported_scheduler_value": True, "value_type": self.value_type},
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_record": True,
            },
        }


def stale_float_value(value: object) -> float:
    """Return canonical non-negative stale-recovery float evidence projection."""
    parsed, _reason = scheduler_float(
        value,
        default=0.0,
        minimum=0.0,
        reason="process_queue_stale_float_rejected",
    )
    return round(parsed, 6)


def stale_optional_float_decision(value: object) -> StaleOptionalFloatDecision:
    """Return a replayable decision for optional stale-recovery float values."""
    if value is None:
        return StaleOptionalFloatDecision(None, "stale_optional_float_missing", "NoneType")
    return StaleOptionalFloatDecision(stale_float_value(value), "stale_optional_float_accepted", no_hook_type_name(value))


def stale_recovered_record_decision(value: object) -> StaleRecoveredRecordDecision:
    """Return a replayable decision for stale-recovery output mappings."""
    if value is None:
        return StaleRecoveredRecordDecision(False, "stale_recovered_record_missing", "NoneType")
    materialized = materialize_scheduler_mapping(value)
    if type(materialized) is dict:
        reason = (
            "stale_recovered_record_materialized_evidence"
            if dict.get(materialized, "unsupported_scheduler_value") is True
            else "stale_recovered_record_accepted"
        )
        return StaleRecoveredRecordDecision(
            True,
            reason,
            no_hook_type_name(value),
            scheduler_str_key_items_from_items(dict.items(materialized)),
        )
    return StaleRecoveredRecordDecision(False, "stale_recovered_record_unsupported", no_hook_type_name(value))


__all__ = (
    "StaleOptionalFloatDecision",
    "StaleRecoveredRecordDecision",
    "stale_float_value",
    "stale_optional_float_decision",
    "stale_recovered_record_decision",
)
