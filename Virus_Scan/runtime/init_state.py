"""Canonical bootstrap/init value owner.

Generated initializer shards publish bootstrap constants directly to this owner.
The owner freezes values at the publication boundary and exposes read-only
snapshots.  There is no secondary registry, module fanout, shared-state
hydration, or old/new publication path.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import math
from threading import RLock
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_duplicate_key,
    no_hook_failure,
    no_hook_json_key,
    no_hook_mapping_items,
)

_MAPPING_PROXY_TYPE: type[MappingProxyType] = type(MappingProxyType({}))
_STANDARD_RUNTIME_OWNER_MODULES = frozenset(("_thread", "_sre", "re"))


def _init_mapping_items_failed(reason: str, value: object) -> tuple[tuple[str, MappingProxyType], ...]:
    return (("init_mapping_items_unavailable", MappingProxyType(no_hook_failure(reason, value))),)


def _invalid_init_item_key(index: int) -> str:
    if type(index) is not int or type(index) is bool:
        return "invalid_init_item"
    return "invalid_init_item_" + int.__str__(index)


def _dict_items_view_type_identity(value: object) -> tuple[str, str]:
    value_type = type(value)
    try:
        type_name = type.__getattribute__(value_type, "__name__")
        module_name = type.__getattribute__(value_type, "__module__")
    except (AttributeError, TypeError):
        return "init_dict_items_type_unavailable", ""
    type_text = str.__str__(type_name) if type(type_name) is str else "init_dict_items_type_unavailable"
    module_text = str.__str__(module_name) if type(module_name) is str else ""
    return type_text, module_text


def _is_exact_dict_items_view(value: object) -> bool:
    type_name, module_name = _dict_items_view_type_identity(value)
    return type_name == "dict_items" and module_name == "builtins"


def _owned_init_value_items(values: dict[str, object]) -> tuple[tuple[str, object], ...]:
    if type(values) is not dict:
        return ()
    return tuple(dict.items(values))


def _init_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    if type(value) is Counter:
        try:
            return tuple(dict.items(value))
        except (TypeError, RuntimeError, RecursionError):
            return _init_mapping_items_failed("init_counter_items_unavailable", value)
    if type(value) is defaultdict:
        try:
            return tuple(dict.items(value))
        except (TypeError, RuntimeError, RecursionError):
            return _init_mapping_items_failed("init_defaultdict_items_unavailable", value)
    return no_hook_mapping_items(value)


def _freeze_mapping_proxy_evidence(value: MappingProxyType) -> tuple[tuple[str, object], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return (("unavailable_reason", "non_materializable_init_value_evidence"),)
    frozen_items: list[tuple[str, object]] = []
    for key, item in items:
        if type(key) is str:
            frozen_items.append((str.__str__(key), _freeze_hashable_value(item)))
    return tuple(sorted(frozen_items, key=lambda row: row[0]))


def _freeze_hashable_value(value: object) -> object:
    if value is None or type(value) is bool or type(value) is int or type(value) is str or type(value) is bytes:
        return value
    if type(value) is float:
        return value if math.isfinite(value) else ("non_finite_init_value_number",)
    if type(value) is tuple:
        return tuple(_freeze_hashable_value(item) for item in value)
    if type(value) is frozenset:
        return frozenset(_freeze_hashable_value(item) for item in value)
    if type(value) is _MAPPING_PROXY_TYPE:
        return _freeze_mapping_proxy_evidence(value)
    return _freeze_mapping_proxy_evidence(MappingProxyType(no_hook_failure("non_hashable_init_set_value", value)))


def _freeze_init_mapping(value: object) -> MappingProxyType:
    items = _init_mapping_items(value)
    if items is None:
        return MappingProxyType(no_hook_failure("non_materializable_init_mapping", value))
    keyed: list[tuple[str, int, object, str, object]] = []
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix="init_value_key")
        keyed.append((key_text, index, item, key_reason, key))
    frozen: dict[str, object] = {}
    for key_text, index, item, key_reason, key in sorted(keyed, key=lambda row: (row[0], row[1])):
        out_key = key_text if key_text not in frozen else no_hook_duplicate_key(key_text, index, rejection="init_duplicate_key_rejected")
        if key_reason:
            frozen[out_key] = MappingProxyType(no_hook_failure(key_reason, key))
        elif type(value) is Counter:
            if type(item) is int and type(item) is not bool:
                frozen[out_key] = item
            else:
                frozen[out_key] = MappingProxyType(no_hook_failure("unsafe_init_counter_value_rejected", item))
        else:
            frozen[out_key] = freeze_init_value(item)
    return MappingProxyType(frozen)


def _freeze_init_set(value: object) -> frozenset[object]:
    return frozenset(
        _freeze_hashable_value(freeze_init_value(item))
        for item in value
    )


def _init_runtime_owner_module(value: object) -> str:
    try:
        module_name = type.__getattribute__(type(value), "__module__")
    except (AttributeError, TypeError):
        return "init_runtime_owner_module_unavailable"
    return str.__str__(module_name) if type(module_name) is str else "init_runtime_owner_module_unavailable"


def _is_standard_runtime_owner(value: object) -> bool:
    return _init_runtime_owner_module(value) in _STANDARD_RUNTIME_OWNER_MODULES


def freeze_init_value(value: object) -> object:
    """Return a deterministic immutable snapshot for init-owned publication.

    The boundary accepts exact owned primitive/container values and known runtime
    owner objects only.  Unknown caller-owned values become explicit immutable
    evidence without invoking caller-owned text, mapping, iteration, numeric, or
    copy protocol hooks.
    """
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is str:
        return str.__str__(value)
    if type(value) is float:
        if math.isfinite(value):
            return value
        return MappingProxyType(no_hook_failure("non_finite_init_value_number", value))
    if type(value) is bytes:
        return bytes(value)
    if type(value) is bytearray:
        return bytes(value)
    if _init_mapping_items(value) is not None:
        return _freeze_init_mapping(value)
    if type(value) in (list, tuple, deque):
        return tuple(freeze_init_value(v) for v in value)
    if type(value) in (set, frozenset):
        return _freeze_init_set(value)
    if _is_standard_runtime_owner(value):
        return value
    return MappingProxyType(no_hook_failure("non_materializable_init_value", value))


def _init_publication_item_pairs(items: object) -> tuple[object, ...]:
    if items is None:
        return ()
    if type(items) in (tuple, list) or _is_exact_dict_items_view(items):
        return tuple(items)
    mapping_items = _init_mapping_items(items)
    if mapping_items is not None:
        return mapping_items
    return (("init_values_materialization", MappingProxyType(no_hook_failure("non_materializable_init_items", items))),)


def _init_publication_pair_parts(pair: object, index: int) -> tuple[object, object, str]:
    if type(pair) in (tuple, list) and len(pair) == 2:
        return pair[0], pair[1], ""
    return _invalid_init_item_key(index), MappingProxyType(no_hook_failure("invalid_init_item", pair)), "invalid_init_item"


class InitStateOwner:
    """Single authority for bootstrap/init values."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._values: dict[str, object] = {}
        self._generation = 0

    def publish(self, name: str, value: object) -> object:
        key, key_reason = no_hook_json_key(name, 0, prefix="init_value_name")
        frozen = MappingProxyType(no_hook_failure(key_reason, name)) if key_reason else freeze_init_value(value)
        with self._lock:
            self._values[key] = frozen
            self._generation += 1
        return frozen

    def publish_many(self, items: object) -> MappingProxyType:
        for index, pair in enumerate(_init_publication_item_pairs(items)):
            name, value, pair_reason = _init_publication_pair_parts(pair, index)
            key, key_reason = no_hook_json_key(name, index, prefix="init_value_name")
            if key_reason:
                frozen = MappingProxyType(no_hook_failure(key_reason, name))
            elif pair_reason:
                frozen = value
            else:
                frozen = freeze_init_value(value)
            with self._lock:
                out_key = key if key not in self._values else no_hook_duplicate_key(key, index, rejection="init_duplicate_key_rejected")
                self._values[out_key] = frozen
                self._generation += 1
        return self.snapshot()["values"]

    def get(self, name: str, default: object = None) -> object:
        key, key_reason = no_hook_json_key(name, 0, prefix="init_value_name")
        if key_reason:
            return MappingProxyType(no_hook_failure(key_reason, name))
        with self._lock:
            return self._values.get(key, default)

    def snapshot(self) -> MappingProxyType:
        with self._lock:
            return MappingProxyType({
                "generation": self._generation,
                "keys": tuple(sorted(self._values)),
                "values": MappingProxyType(
                    dict(_owned_init_value_items(self._values))
                ),
            })


_INIT_STATE = InitStateOwner()


def publish_init_value(name: str, value: object) -> object:
    return _INIT_STATE.publish(name, value)


def publish_init_values(items: object) -> MappingProxyType:
    return _INIT_STATE.publish_many(items)


def get_init_value(name: str, default: object = None) -> object:
    return _INIT_STATE.get(name, default)


def init_state_snapshot() -> MappingProxyType:
    return _INIT_STATE.snapshot()


__all__ = (
    "InitStateOwner",
    "freeze_init_value",
    "get_init_value",
    "init_state_snapshot",
    "publish_init_value",
    "publish_init_values",
)
