"""Detection-owned immutable registry publication snapshot helpers.

Detection registries publish immutable snapshots for detection consumers without
mutating runtime init state or hydrating global defaults at import time.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import math
from types import MappingProxyType
from typing import Iterable

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_failure,
    no_hook_internal_frozen_dataclass_status,
    no_hook_json_key,
    no_hook_mapping_items,
)

_MAPPING_PROXY_TYPE: type[object] = type(MappingProxyType({}))
_NO_MAPPING_ITEMS = None


def _dataclass_status(*, ok: bool, reason: str) -> tuple[bool, str]:
    return ok, reason


def _indexed_key(key_text: str, index: int) -> str:
    return key_text + str.__str__("#") + int.__str__(index)


def _invalid_registry_item_name(index: int) -> str:
    return "invalid_detection_registry_item_" + int.__str__(index)


def _is_detection_owned_frozen_dataclass_status(value: object) -> tuple[bool, str]:
    ok, reason = no_hook_internal_frozen_dataclass_status(value)
    return _dataclass_status(ok=ok, reason=reason)


def _is_detection_owned_frozen_dataclass(value: object) -> bool:
    ok, _reason = _is_detection_owned_frozen_dataclass_status(value)
    return ok


def _registry_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    if type(value) is Counter or type(value) is defaultdict:
        items = no_hook_mapping_items(value, allow_dict_subclass=True)
        return items if items is not None else _NO_MAPPING_ITEMS
    return no_hook_mapping_items(value)


def _freeze_registry_mapping(value: object) -> MappingProxyType:
    items = _registry_mapping_items(value)
    if items is None:
        return MappingProxyType(no_hook_failure("non_materializable_detection_registry_mapping", value))
    keyed: list[tuple[str, int, object, str, object]] = []
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix="detection_registry_key")
        keyed.append((key_text, index, item, key_reason, key))
    frozen: dict[str, object] = {}
    for key_text, index, item, key_reason, key in sorted(keyed, key=lambda row: (row[0], row[1])):
        out_key = key_text if key_text not in frozen else _indexed_key(key_text, index)
        if key_reason:
            frozen[out_key] = MappingProxyType(no_hook_failure(key_reason, key))
        else:
            frozen[out_key] = freeze_registry_publication(item)
    return MappingProxyType(frozen)



def _freeze_direct_registry_value(value: object) -> tuple[bool, object]:
    matched = True
    if value is None or type(value) is bool or type(value) is int:
        frozen = value
    elif type(value) is str:
        frozen = str.__str__(value)
    elif type(value) is float:
        frozen = value if math.isfinite(value) else MappingProxyType(
            no_hook_failure("non_finite_detection_registry_number", value)
        )
    elif type(value) is bytes:
        frozen = bytes(value)
    elif type(value) is bytearray:
        frozen = bytes(value)
    else:
        matched = False
        frozen = value
    return matched, frozen


def freeze_registry_publication(value: object) -> object:
    matched, frozen = _freeze_direct_registry_value(value)
    if matched:
        return frozen
    if _registry_mapping_items(value) is not None:
        return _freeze_registry_mapping(value)
    if type(value) in (list, tuple, deque):
        return tuple(freeze_registry_publication(item) for item in value)
    if type(value) in (set, frozenset):
        return frozenset(freeze_registry_publication(item) for item in value)
    if _is_detection_owned_frozen_dataclass(value):
        return value
    return MappingProxyType(no_hook_failure("non_materializable_detection_registry_value", value))


def _publication_item_pairs(items: Iterable[tuple[str, object]]) -> tuple[object, ...]:
    if items is None:
        return ()
    if type(items) in (tuple, list):
        return tuple(items)
    return (("init_values_materialization", MappingProxyType(no_hook_failure("non_materializable_detection_registry_items", items))),)


def _publication_pair_parts(pair: object, index: int) -> tuple[object, object, str]:
    if type(pair) in (tuple, list) and len(pair) == 2:
        return pair[0], pair[1], ""
    return _invalid_registry_item_name(index), MappingProxyType(no_hook_failure("invalid_detection_registry_item", pair)), "invalid_detection_registry_item"


def publish_init_values(items: Iterable[tuple[str, object]]) -> MappingProxyType:
    """Return a frozen registry publication view owned by detection."""
    frozen: dict[str, object] = {}
    for index, pair in enumerate(_publication_item_pairs(items)):
        name, value, pair_reason = _publication_pair_parts(pair, index)
        key_text, key_reason = no_hook_json_key(name, index, prefix="detection_registry_name")
        out_key = key_text if key_text not in frozen else _indexed_key(key_text, index)
        if key_reason:
            frozen[out_key] = MappingProxyType(no_hook_failure(key_reason, name))
        elif pair_reason:
            frozen[out_key] = value
        else:
            frozen[out_key] = freeze_registry_publication(value)
    return MappingProxyType(frozen)


__all__ = ("freeze_registry_publication", "publish_init_values")
