"""Typed raw-queue quarantine decision helpers."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text


@dataclass(frozen=True)
class RawQueueBoolDecision:
    """Replayable no-hook boolean coercion decision."""

    accepted: bool
    value: bool
    reason: str

    def as_bool(self) -> bool:
        """Return the canonical boolean projection for quarantine callers."""
        return self.value


@dataclass(frozen=True)
class RawQueueMappingDecision:
    """Replayable no-hook mapping materialization decision."""

    accepted: bool
    mapping: Mapping[str, object]
    reason: str

    def as_mapping_or_none(self) -> dict[str, object] | None:
        """Return the canonical mapping/None projection for quarantine callers."""
        if not self.accepted:
            return None
        return dict(self.mapping)


@dataclass(frozen=True)
class RawQueueQuarantineDecision:
    """Replayable raw-queue quarantine outcome."""

    quarantined: bool
    reason: str
    path_text: str
    destination_text: str
    source_state: str
    detail: str


_EMPTY_MAPPING: Mapping[str, object] = MappingProxyType({})


def raw_queue_bool_decision(value: object, *, rejected_reason: str) -> RawQueueBoolDecision:
    """Return a typed no-hook boolean decision without invoking hooks."""
    if type(value) is bool:
        return RawQueueBoolDecision(accepted=True, value=value, reason="")
    if type(value) is int and type(value) is not bool:
        return RawQueueBoolDecision(accepted=True, value=value != 0, reason="")
    return RawQueueBoolDecision(accepted=False, value=False, reason=rejected_reason)


def raw_queue_mapping_decision(value: object, *, rejected_reason: str) -> RawQueueMappingDecision:
    """Return a typed no-hook mapping decision without invoking hooks."""
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return RawQueueMappingDecision(accepted=False, mapping=_EMPTY_MAPPING, reason=rejected_reason)
    return RawQueueMappingDecision(accepted=True, mapping=MappingProxyType(scheduler_str_key_mapping_from_items(items)), reason="")


def raw_queue_quarantine_rejected(reason: str, *, path: object = "", detail: str = "") -> RawQueueQuarantineDecision:
    """Return a typed rejected quarantine decision."""
    path_text, path_reason = scheduler_path_text(path)
    return RawQueueQuarantineDecision(quarantined=False, reason=reason, path_text=path_text, destination_text="", source_state="", detail=detail if detail != "" else path_reason)


def raw_queue_quarantine_accepted(*, path: object, destination: object, source_state: str) -> RawQueueQuarantineDecision:
    """Return a typed accepted quarantine decision."""
    path_text, path_reason = scheduler_path_text(path)
    destination_text, destination_reason = scheduler_path_text(destination)
    detail = path_reason if path_reason != "" else destination_reason
    return RawQueueQuarantineDecision(quarantined=True, reason="quarantined", path_text=path_text, destination_text=destination_text, source_state=source_state, detail=detail)


__all__ = (
    "RawQueueBoolDecision",
    "RawQueueMappingDecision",
    "RawQueueQuarantineDecision",
    "raw_queue_bool_decision",
    "raw_queue_mapping_decision",
    "raw_queue_quarantine_accepted",
    "raw_queue_quarantine_rejected",
)
