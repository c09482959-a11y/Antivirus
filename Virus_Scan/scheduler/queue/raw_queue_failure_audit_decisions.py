"""Replayable decisions for failed raw-queue audit projections."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_items_from_items
from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name


@dataclass(frozen=True, slots=True)
class FailedQueueNameDecision:
    """Typed no-hook decision for failed-queue entry names."""

    accepted: bool
    text: str
    reason: str
    value_type: str


@dataclass(frozen=True, slots=True)
class FailedQueueMappingDecision:
    """Typed no-hook decision for failed-queue metadata mappings."""

    accepted: bool
    reason: str
    value_type: str
    items: tuple[tuple[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))

    def as_mapping(self) -> dict[str, object]:
        """Return the canonical dict projection while preserving replayable decision state."""
        return dict(self.items) if self.accepted else {}


def failed_queue_name_decision(value: object) -> FailedQueueNameDecision:
    """Return a replayable failed-queue name decision without invoking caller hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_failed_queue_name",
        unsupported_reason="unsafe_failed_queue_name_rejected",
    )
    if reason or text == "":
        return FailedQueueNameDecision(
            accepted=False,
            text="",
            reason=reason or "empty_failed_queue_name_rejected",
            value_type=no_hook_type_name(value),
        )
    return FailedQueueNameDecision(
        accepted=True,
        text=text,
        reason="failed_queue_name_accepted",
        value_type=no_hook_type_name(value),
    )


def failed_queue_mapping_decision(value: object) -> FailedQueueMappingDecision:
    """Return a replayable failed-queue mapping decision without invoking caller hooks."""
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return FailedQueueMappingDecision(
            accepted=False,
            reason="failed_queue_mapping_unavailable" if value is None else "failed_queue_mapping_unsupported",
            value_type=no_hook_type_name(value),
        )
    return FailedQueueMappingDecision(
        accepted=True,
        reason="failed_queue_mapping_accepted",
        value_type=no_hook_type_name(value),
        items=scheduler_str_key_items_from_items(items),
    )


__all__ = (
    "FailedQueueMappingDecision",
    "FailedQueueNameDecision",
    "failed_queue_mapping_decision",
    "failed_queue_name_decision",
)
