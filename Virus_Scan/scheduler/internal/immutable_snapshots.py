"""Durable scheduler JSON/evidence/replay snapshot helpers."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_json_sort_key
from Virus_Scan.scheduler.internal.immutable_outputs import (
    FrozenSchedulerMapping,
    materialize_scheduler_mapping,
    unsupported_scheduler_value_evidence,
)


def _freeze_materialized_scheduler_value(value: object) -> object:
    """Freeze already-materialized JSON-safe scheduler values without retaining caller objects."""
    if value is None or type(value) is bool or type(value) is int or type(value) is float:
        return value
    if type(value) is str:
        return str.__str__(value)
    if type(value) is dict:
        return FrozenSchedulerMapping(
            tuple(
                (str.__str__(key), _freeze_materialized_scheduler_value(item))
                for key, item in sorted(
                    value.items(),
                    key=lambda pair: str.__str__(pair[0]) if type(pair[0]) is str else "",
                )
                if type(key) is str
            )
        )
    if type(value) is list or type(value) is tuple:
        return tuple(_freeze_materialized_scheduler_value(item) for item in value)
    return FrozenSchedulerMapping(
        (("unsupported_scheduler_snapshot_value", _freeze_materialized_scheduler_value(unsupported_scheduler_value_evidence(value))),)
    )


def immutable_snapshot_value(value: object, *, field_name: str = "scheduler_value") -> object:
    """Return a JSON/evidence/replay snapshot that never retains caller-owned objects.

    This is the durable snapshot path. It is intentionally separate from
    ``immutable_value()``, which freezes live scheduler carrier records and
    rejects unsupported external objects with explicit scheduler evidence.
    """
    materialized = materialize_scheduler_mapping(value)
    if type(materialized) is dict and dict.get(materialized, "unsupported_scheduler_value") is True and type(field_name) is str:
        materialized["field_name"] = str.__str__(field_name)
    return _freeze_materialized_scheduler_value(materialized)


def immutable_snapshot_mapping(value: object, *, field_name: str = "scheduler_value") -> Mapping[str, object]:
    snapshot = immutable_snapshot_value(value, field_name=field_name)
    if type(snapshot) is FrozenSchedulerMapping:
        return snapshot
    return immutable_snapshot_value(unsupported_scheduler_value_evidence(value, field_name=field_name))


def immutable_snapshot_tuple(value: object = ()) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) in {list, tuple, set, frozenset}:
        items = value
    else:
        return (immutable_snapshot_value(value),)
    materialized_items = [immutable_snapshot_value(item) for item in items]
    if type(value) in {set, frozenset}:
        return tuple(sorted(materialized_items, key=lambda item: no_hook_json_sort_key(materialize_scheduler_mapping(item))))
    return tuple(materialized_items)


__all__ = ("immutable_snapshot_mapping", "immutable_snapshot_tuple", "immutable_snapshot_value")
