"""Replayable retry scan-integrity mapping decisions."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_items_from_items
from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name


@dataclass(frozen=True, slots=True)
class RetryIntegrityMappingDecision:
    accepted: bool
    reason: str
    value_type: str
    items: tuple[tuple[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))

    def as_optional_mapping(self) -> dict[str, object] | None:
        if not self.accepted:
            return None
        return dict(self.items)


@dataclass(frozen=True, slots=True)
class RetryIntegrityMissingDecision:
    reason: str
    value_type: str
    missing: bool

    def as_integrity(self) -> dict[str, object]:
        return {}


def retry_integrity_mapping_decision(value: object) -> RetryIntegrityMappingDecision:
    items = no_hook_mapping_items(value)
    if items is None:
        return RetryIntegrityMappingDecision(accepted=False, reason="retry_integrity_mapping_rejected", value_type=no_hook_type_name(value))
    return RetryIntegrityMappingDecision(
        accepted=True,
        reason="retry_integrity_mapping_accepted",
        value_type=no_hook_type_name(value),
        items=scheduler_str_key_items_from_items(items),
    )


def retry_integrity_missing_decision(value: object) -> RetryIntegrityMissingDecision:
    return RetryIntegrityMissingDecision("retry_integrity_missing", no_hook_type_name(value), missing=True)


__all__ = (
    "RetryIntegrityMappingDecision",
    "RetryIntegrityMissingDecision",
    "retry_integrity_mapping_decision",
    "retry_integrity_missing_decision",
)
