"""Replayable decisions for raw queue integrity projections."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_type_name,
)

_DEGRADED_KEYS = frozenset(("had_degraded_stage", "missing_chunks", "raw_failed", "raw_failures", "partial_retry"))


@dataclass(frozen=True, slots=True)
class RawIntegrityTruthyDecision:
    """Typed decision for raw integrity truthy-value projection."""

    truthy: bool
    reason: str
    value_type: str

    def as_bool(self) -> bool:
        """Return the canonical bool projection for raw integrity callers."""
        return self.truthy


@dataclass(frozen=True, slots=True)
class RawIntegrityDegradedDecision:
    """Typed decision for raw integrity degraded-state projection."""

    degraded: bool
    reason: str
    snapshot_type: str
    matched_key: str = ""

    def as_bool(self) -> bool:
        """Return the canonical bool projection for raw integrity callers."""
        return self.degraded


def raw_integrity_truthy_decision(value: object) -> RawIntegrityTruthyDecision:
    """Return a replayable no-hook truthiness decision for raw integrity values."""
    if value is None:
        return RawIntegrityTruthyDecision(truthy=False, reason="raw_integrity_value_missing", value_type="NoneType")
    if type(value) is bool:
        return RawIntegrityTruthyDecision(value, "raw_integrity_bool_value", "bool")
    if type(value) is int:
        return RawIntegrityTruthyDecision(value != 0, "raw_integrity_int_value", "int")
    if type(value) is float:
        return RawIntegrityTruthyDecision(value != 0.0, "raw_integrity_float_value", "float")
    if type(value) is str:
        return RawIntegrityTruthyDecision(value != "", "raw_integrity_text_value", "str")
    if type(value) in (list, tuple, set, frozenset, dict):
        return RawIntegrityTruthyDecision(len(value) > 0, "raw_integrity_builtin_container_value", no_hook_type_name(value))
    if no_hook_mapping_items(value) is not None:
        return RawIntegrityTruthyDecision(truthy=True, reason="raw_integrity_mapping_value", value_type=no_hook_type_name(value))
    if no_hook_sequence_items(value):
        return RawIntegrityTruthyDecision(truthy=True, reason="raw_integrity_sequence_value", value_type=no_hook_type_name(value))
    return RawIntegrityTruthyDecision(truthy=True, reason="raw_integrity_unsupported_value_assumed_truthy", value_type=no_hook_type_name(value))


def raw_integrity_degraded_decision(integrity: Mapping[str, object] | None) -> RawIntegrityDegradedDecision:
    """Return a replayable no-hook degraded decision for raw integrity snapshots."""
    if integrity is None:
        items: tuple[tuple[object, object], ...] = ()
    else:
        mapping_items = no_hook_mapping_items(integrity, allow_dict_subclass=True)
        if mapping_items is None:
            return RawIntegrityDegradedDecision(degraded=True, reason="raw_integrity_snapshot_rejected", snapshot_type=no_hook_type_name(integrity))
        items = mapping_items
    snapshot = scheduler_str_key_mapping_from_items(items)
    for key in _DEGRADED_KEYS:
        if raw_integrity_truthy_decision(dict.get(snapshot, key)).truthy:
            return RawIntegrityDegradedDecision(degraded=True, reason="raw_integrity_degraded_key_present", snapshot_type=no_hook_type_name(integrity), matched_key=key)
    return RawIntegrityDegradedDecision(degraded=False, reason="raw_integrity_no_degraded_keys", snapshot_type=no_hook_type_name(integrity))


__all__ = (
    "RawIntegrityDegradedDecision",
    "RawIntegrityTruthyDecision",
    "raw_integrity_degraded_decision",
    "raw_integrity_truthy_decision",
)
