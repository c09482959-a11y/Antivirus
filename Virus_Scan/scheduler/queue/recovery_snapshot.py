"""Replay-stable queue recovery snapshot ownership."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import (
    materialize_json_no_hook,
    no_hook_json_key,
    no_hook_json_sort_key,
    no_hook_mapping_items,
)
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.queue.recovery_contract import _LIVE_RUNTIME_KEYS, _QUEUE_INFO_LIVE_KEYS

_VOLATILE_RECOVERY_KEYS = frozenset(
    tuple(_LIVE_RUNTIME_KEYS)
    + tuple(_QUEUE_INFO_LIVE_KEYS)
    + (
        "time",
        "iso",
        "retry_pending_time",
        "retry_pending_iso",
        "claimed_at",
        "finished_at",
        "duration",
        "traceback",
    )
)


def _unsupported_recovery_snapshot(value: object, *, field_name: str) -> dict[str, object]:
    evidence = unsupported_scheduler_value_evidence(value, field_name=field_name)
    evidence.update(
        {
            "scheduler_recovery_snapshot_unavailable": True,
            "reason": "unsupported_recovery_snapshot_value",
        }
    )
    return evidence


def _stable_recovery_value(value: object, *, field_name: str = "recovery_snapshot") -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        keyed: list[tuple[str, int, object, str, object]] = []
        for index, (key, item) in enumerate(items):
            key_text, key_reason = no_hook_json_key(key, index, prefix="recovery_snapshot_key")
            if key_reason == "" and key_text in _VOLATILE_RECOVERY_KEYS:
                continue
            keyed.append((key_text, index, item, key_reason, key))
        out: dict[str, object] = {}
        for key_text, index, item, key_reason, original_key in sorted(keyed, key=lambda row: (row[0], row[1])):
            output_key = key_text if key_text not in out else str.__str__(key_text) + "#" + int.__str__(index)
            if key_reason:
                out[output_key] = _unsupported_recovery_snapshot(original_key, field_name=output_key)
            else:
                out[output_key] = _stable_recovery_value(item, field_name=output_key)
        return out
    if type(value) in (list, tuple):
        base_field_name = str.__str__(field_name) if type(field_name) is str and field_name else "recovery_snapshot"
        return [_stable_recovery_value(item, field_name=base_field_name + "_" + int.__str__(index)) for index, item in enumerate(value)]
    if type(value) in (set, frozenset):
        materialized = [_stable_recovery_value(item, field_name=field_name) for item in value]
        return sorted(materialized, key=no_hook_json_sort_key)
    materialized = materialize_json_no_hook(value, context="scheduler_recovery_snapshot")
    if type(materialized) is dict and materialized.get("unavailable_reason"):
        return _unsupported_recovery_snapshot(value, field_name=field_name)
    return materialized


def deterministic_recovery_snapshot(record: object) -> dict[str, object]:
    """Return replay-stable scheduler recovery state with live volatility removed.

    The recovery snapshot is a scheduler/replay evidence boundary.  It accepts
    exact built-in mappings and exact built-in containers only, removes live
    process/clock fields, and rejects caller-owned mapping-like or iterable
    objects with explicit deterministic evidence instead of invoking custom
    ``items()``, iteration, string, repr, format, or numeric hooks.
    """
    items = no_hook_mapping_items(record)
    if items is None:
        return _unsupported_recovery_snapshot(record, field_name="recovery_snapshot")
    stable = _stable_recovery_value(record)
    if type(stable) is dict:
        return stable
    return _unsupported_recovery_snapshot(record, field_name="recovery_snapshot")
