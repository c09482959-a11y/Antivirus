"""Immutable scheduler cross-area output contracts."""
from __future__ import annotations

import json
import math
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_dataclass_ownership import _internal_frozen_dataclass_decision
from Virus_Scan.scheduler.internal.immutable_output_decisions import (
    ImmutableTupleDecision,
    TuplePairItemsDecision,
    immutable_tuple_available,
    immutable_tuple_rejected,
    tuple_pair_items_available,
    tuple_pair_items_rejected,
)
from Virus_Scan.scheduler.internal.immutable_materialization import materialize_scheduler_mapping_decision
from Virus_Scan.scheduler.internal.immutable_output_support import (
    FrozenSchedulerMapping,
    _materialize_scheduler_key,
    is_trusted_scheduler_materialization_value,
    unsupported_scheduler_value_evidence,
)


_TUPLE_PAIR_ITEMS_UNAVAILABLE: tuple[tuple[object, object], ...] | None = None


def tuple_pair_items_decision(value: tuple[object, ...]) -> TuplePairItemsDecision:
    value_type = no_hook_type_name(value)
    pairs: list[tuple[object, object]] = []
    for index, item in enumerate(value):
        if type(item) is tuple and len(item) >= 2:
            pairs.append((item[0], item[1]))
            continue
        if type(item) is list and len(item) >= 2:
            pairs.append((item[0], item[1]))
            continue
        return tuple_pair_items_rejected(
            "tuple_pair_item_shape_rejected",
            value_type,
            failed_index=index,
        )
    return tuple_pair_items_available(tuple(pairs), value_type)


def immutable_mapping(value: Mapping[str, object] | tuple[tuple[object, object], ...] | None = None) -> FrozenSchedulerMapping:
    """Return a recursively immutable deterministic scheduler mapping snapshot."""
    if value is None:
        return FrozenSchedulerMapping()
    if type(value) is FrozenSchedulerMapping:
        return value
    items = no_hook_mapping_items(value)
    if items is None:
        if type(value) is tuple:
            tuple_items_decision = tuple_pair_items_decision(value)
            items = tuple_items_decision.items if tuple_items_decision.accepted else _TUPLE_PAIR_ITEMS_UNAVAILABLE
    if items is None:
        return FrozenSchedulerMapping((
            ("scheduler_mapping_unavailable", True),
            ("reason", "non_materializable_scheduler_mapping"),
            ("evidence", unsupported_scheduler_value_evidence(value, field_name="scheduler_mapping")),
        ))
    frozen: list[tuple[str, object]] = []
    for index, (key, item) in enumerate(items):
        materialized_key = _materialize_scheduler_key(key, index)
        if materialized_key.startswith("unsupported_scheduler_key_"):
            frozen.append((materialized_key, unsupported_scheduler_value_evidence(key, field_name=materialized_key)))
            continue
        frozen.append((materialized_key, immutable_value(item)))
    return FrozenSchedulerMapping(tuple(sorted(frozen, key=lambda pair: pair[0])))


def immutable_value(value: object) -> object:
    """Freeze container values before crossing scheduler ownership boundaries."""
    if type(value) is FrozenSchedulerMapping:
        return value
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is float:
        if math.isfinite(value):
            return value
        return unsupported_scheduler_value_evidence(value)
    if no_hook_mapping_items(value) is not None:
        return immutable_mapping(value)
    if type(value) in {list, tuple}:
        return tuple(immutable_value(item) for item in value)
    if type(value) in {set, frozenset}:
        safe_items = tuple(immutable_value(item) for item in value)
        return tuple(sorted(safe_items, key=lambda item: json.dumps(materialize_scheduler_mapping(item), sort_keys=True, separators=(",", ":"), allow_nan=False)))
    if _internal_frozen_dataclass_decision(value).accepted:
        return value
    return unsupported_scheduler_value_evidence(value)


def immutable_tuple_decision(value: object = ()) -> ImmutableTupleDecision:
    value_type = no_hook_type_name(value)
    if value is None:
        evidence = unsupported_scheduler_value_evidence(value, field_name="scheduler_tuple")
        return immutable_tuple_rejected(
            "scheduler_tuple_missing",
            value_type,
            evidence=evidence,
        )
    if type(value) in {list, tuple}:
        return immutable_tuple_available(
            tuple(immutable_value(item) for item in value),
            value_type,
        )
    evidence = unsupported_scheduler_value_evidence(value, field_name="scheduler_tuple")
    return immutable_tuple_available(
        (evidence,),
        value_type,
        reason="scheduler_tuple_degraded_unsupported_value",
        evidence=evidence,
    )


def immutable_tuple(value: object = ()) -> tuple[object, ...]:
    return immutable_tuple_decision(value).items


def materialize_scheduler_mapping(value: object) -> object:
    """Convert immutable scheduler snapshots to plain containers at serialization edges only."""
    return materialize_scheduler_mapping_decision(value).value


__all__ = (
    "FrozenSchedulerMapping",
    "immutable_mapping",
    "immutable_tuple",
    "immutable_tuple_decision",
    "immutable_value",
    "is_trusted_scheduler_materialization_value",
    "materialize_scheduler_mapping",
    "tuple_pair_items_decision",
    "unsupported_scheduler_value_evidence",
)
