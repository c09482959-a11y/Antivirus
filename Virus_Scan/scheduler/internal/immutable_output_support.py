"""No-hook support primitives for immutable scheduler outputs."""
from __future__ import annotations

from collections.abc import Iterator, Mapping as MappingABC
import math
from types import MappingProxyType

from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.immutable_output_decisions import (
    FrozenSchedulerEqualityDecision,
    FrozenSchedulerItemsDecision,
    frozen_items_available,
    frozen_items_rejected,
    frozen_mapping_equality,
)
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.immutable_dataclass_ownership import _internal_frozen_dataclass_decision


_FROZEN_ITEMS_UNAVAILABLE = None


class FrozenSchedulerMapping(MappingABC):
    """Tuple-backed immutable mapping used for scheduler ownership boundaries.

    The class intentionally does not retain a mutable dictionary internally.
    Lookups are linear, which is acceptable for boundary snapshots and avoids
    hidden mutable dictionary state crossing scheduler areas.
    """

    __slots__ = ("_items",)
    _items: tuple[tuple[str, object], ...]

    def __init__(self, items: tuple[tuple[str, object], ...] = ()) -> None:
        frozen_items: list[tuple[str, object]] = []
        for index, item in enumerate(items):
            if type(item) is not tuple or len(item) < 2:
                item_key = "unsupported_scheduler_item_" + int.__str__(index)
                frozen_items.append((
                    item_key,
                    unsupported_scheduler_value_evidence(item, field_name=item_key),
                ))
                continue
            key, value = item[0], item[1]
            frozen_items.append((_materialize_scheduler_key(key, index), value))
        object.__setattr__(self, "_items", tuple(frozen_items))

    def __getitem__(self, key: str) -> object:
        requested = _materialize_scheduler_key(key, 0)
        if requested.startswith("unsupported_scheduler_key_"):
            raise KeyError(no_hook_type_name(key))
        for item_key, item_value in self._items:
            if item_key == requested:
                return item_value
        raise KeyError(requested)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _value in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return "FrozenSchedulerMapping(size=" + int.__str__(len(self._items)) + ")"

    def __hash__(self) -> int:
        return hash(self._items)

    def __eq__(self, other: object) -> bool:
        return frozen_scheduler_mapping_equality_decision(self, other).equal


def frozen_scheduler_mapping_equality_decision(
    left: FrozenSchedulerMapping,
    other: object,
) -> FrozenSchedulerEqualityDecision:
    compared_type = no_hook_type_name(other)
    left_decision = frozen_scheduler_items_decision(left)
    if not left_decision.accepted:
        return frozen_mapping_equality(equal=False, reason="left_items_unavailable", compared_type=compared_type)
    left_items = left_decision.items
    if type(other) is FrozenSchedulerMapping:
        other_decision = frozen_scheduler_items_decision(other)
        return frozen_mapping_equality(equal=other_decision.accepted and left_items == other_decision.items, reason="exact_frozen_scheduler_mapping", compared_type=compared_type)
    if type(other) is tuple:
        return frozen_mapping_equality(equal=left_items == other, reason="tuple_item_snapshot", compared_type=compared_type)
    if type(other) is dict:
        items = no_hook_mapping_items(other)
        if items is None:
            return frozen_mapping_equality(equal=False, reason="dict_items_unavailable", compared_type=compared_type)
        frozen = tuple(sorted((_materialize_scheduler_key(key, index), value) for index, (key, value) in enumerate(items)))
        return frozen_mapping_equality(equal=left_items == frozen, reason="dict_item_snapshot", compared_type=compared_type)
    return frozen_mapping_equality(equal=False, reason="unsupported_comparison_type", compared_type=compared_type)


def frozen_scheduler_items_decision(value: object) -> FrozenSchedulerItemsDecision:
    """Return a replayable exact-item decision for the owned frozen mapping type.

    Subclasses are intentionally rejected. A hostile subclass can bypass
    ``__init__`` and install caller-owned descriptors/properties for ``_items``;
    accepting only the exact owned ``FrozenSchedulerMapping`` type prevents those
    hooks from executing at scheduler evidence/materialization boundaries.
    """
    value_type = no_hook_type_name(value)
    if type(value) is not FrozenSchedulerMapping:
        return frozen_items_rejected("not_exact_frozen_scheduler_mapping", value_type)
    items = scheduler_exact_attr(value, "_items", owner_type=FrozenSchedulerMapping, default=_FROZEN_ITEMS_UNAVAILABLE)
    if type(items) is not tuple:
        return frozen_items_rejected("frozen_scheduler_items_unavailable", value_type)
    for item in items:
        if type(item) is not tuple or len(item) < 2 or type(item[0]) is not str:
            return frozen_items_rejected("invalid_frozen_scheduler_item_shape", value_type)
    return frozen_items_available(items)


def unsupported_scheduler_value_evidence(value: object, *, field_name: str = "scheduler_value") -> dict[str, object]:
    value_type = no_hook_type_name(value)
    return {
        "unsupported_scheduler_value": True,
        "status": "failed",
        "failed": True,
        "stage": "scheduler_json_materialization",
        "state": "failed",
        "error_category": "scheduler_json_materialization_unsupported",
        "error_source": "scheduler.internal.immutable_outputs",
        "message": "unsupported scheduler value cannot be materialized without caller hooks",
        "field_name": field_name if type(field_name) is str else "scheduler_value",
        "value_type": value_type,
        "context": {
            "unsupported_scheduler_value": True,
            "value_type": value_type,
        },
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }


def _materialize_scheduler_key(key: object, index: int) -> str:
    if type(key) is str:
        return str.__str__(key)
    if type(key) is bool:
        return "true" if key else "false"
    if type(key) is int:
        return int.__str__(key)
    if type(key) is float and math.isfinite(key):
        return float.__str__(key)
    return "unsupported_scheduler_key_" + int.__str__(index)


def is_trusted_scheduler_materialization_value(value: object) -> bool:
    return (
        type(value) is FrozenSchedulerMapping
        or type(value) is MappingProxyType
        or _internal_frozen_dataclass_decision(value).accepted
    )


__all__ = (
    "FrozenSchedulerMapping",
    "_materialize_scheduler_key",
    "frozen_scheduler_items_decision",
    "frozen_scheduler_mapping_equality_decision",
    "is_trusted_scheduler_materialization_value",
    "unsupported_scheduler_value_evidence",
)
