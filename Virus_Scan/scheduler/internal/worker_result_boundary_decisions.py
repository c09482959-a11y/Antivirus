"""Replayable no-hook decisions for scheduler worker-result boundaries."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_items_from_items
from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping


@dataclass(frozen=True, slots=True)
class SchedulerOwnedMappingDecision:
    """Replayable decision for scheduler-owned mapping materialization."""

    accepted: bool
    reason: str
    value_type: str
    items: tuple[tuple[object, object], ...] = ()
    rejected_value: dict[object, object] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))

    def as_snapshot(self) -> dict[object, object] | None:
        return dict(self.items) if self.accepted else self.rejected_value


@dataclass(frozen=True, slots=True)
class SchedulerScanIntegrityDecision:
    """Replayable decision for scan-integrity mapping materialization."""

    accepted: bool
    reason: str
    value_type: str
    items: tuple[tuple[str, object], ...] = ()
    evidence: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        object.__setattr__(self, "evidence", immutable_mapping(self.evidence))

    def as_snapshot(self) -> dict[str, object]:
        return dict(self.items) if self.accepted else dict(self.evidence)


def scheduler_owned_mapping_decision(value: object) -> SchedulerOwnedMappingDecision:
    items = no_hook_mapping_items(value)
    if items is None:
        return SchedulerOwnedMappingDecision(
            accepted=False,
            reason="scheduler_owned_mapping_not_materializable",
            value_type=no_hook_type_name(value),
        )
    return SchedulerOwnedMappingDecision(
        accepted=True,
        reason="scheduler_owned_mapping_materialized",
        value_type=no_hook_type_name(value),
        items=items,
    )


def scheduler_scan_integrity_decision(
    value: object,
    *,
    unavailable_reason: str,
    original_type_field: str,
    unavailable_flag: str = "scan_integrity_unavailable",
    unavailable_reason_field: str = "scan_integrity_unavailable_reason",
) -> SchedulerScanIntegrityDecision:
    mapping_decision = scheduler_owned_mapping_decision(value)
    if mapping_decision.accepted:
        return SchedulerScanIntegrityDecision(
            accepted=True,
            reason="scan_integrity_materialized",
            value_type=mapping_decision.value_type,
            items=scheduler_str_key_items_from_items(mapping_decision.items),
        )
    reason = "missing_scan_integrity" if value is None else unavailable_reason
    return SchedulerScanIntegrityDecision(
        accepted=False,
        reason=reason,
        value_type=mapping_decision.value_type,
        evidence={
            unavailable_flag: True,
            "scan_integrity_unavailable": True,
            "scan_integrity_unavailable_reason": reason,
            unavailable_reason_field: reason,
            original_type_field: mapping_decision.value_type,
            "queue_failure": True,
            "allow_learning": False,
        },
    )


__all__ = (
    "SchedulerOwnedMappingDecision",
    "SchedulerScanIntegrityDecision",
    "scheduler_owned_mapping_decision",
    "scheduler_scan_integrity_decision",
)
