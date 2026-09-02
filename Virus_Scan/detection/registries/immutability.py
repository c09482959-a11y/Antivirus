"""Canonical immutable registry snapshot helpers for detection registries."""

from __future__ import annotations

import math
from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_duplicate_key,
    no_hook_json_key,
    no_hook_mapping_items,
    no_hook_type_name,
)

_MAPPING_PROXY_TYPE: type[object] = type(MappingProxyType({}))


def _registry_unavailable_record(reason: str, value: object) -> MappingProxyType:
    return MappingProxyType({
        "value": None,
        "unavailable_reason": reason,
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "replay_record_required": True,
    })


def _registry_hashable_unavailable(reason: str, value: object) -> tuple[tuple[str, object], ...]:
    return (
        ("value", None),
        ("unavailable_reason", reason),
        ("value_type", no_hook_type_name(value)),
        ("final_json_must_record", True),
        ("replay_record_required", True),
    )


def _registry_value_sort_key(value: object) -> str:
    """Return a deterministic sort key without caller-owned hooks."""
    if type(value) is str:
        return "str:" + str.__str__(value)
    if isinstance(value, str):
        return "str:" + str.__str__(value)
    if type(value) is bool:
        return "bool:" + bool.__str__(value)
    if type(value) is int:
        return "int:" + int.__str__(value)
    if type(value) is float:
        if math.isfinite(value):
            return "float:" + float.__str__(value)
        return "float:non_finite"
    if type(value) in (bytes, bytearray, memoryview):
        return "bytes:" + bytes(value).hex()
    return no_hook_type_name(value) + ":unavailable"


def _freeze_registry_set_item(value: object) -> object:
    if value is None or type(value) in (bool, int, float, str, bytes):
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) in (bytearray, memoryview):
        return bytes(value)
    if no_hook_mapping_items(value) is not None or isinstance(value, Mapping):
        return _registry_hashable_unavailable("registry_set_mapping_value_unavailable", value)
    if type(value) in (set, frozenset, list, tuple):
        return tuple(_freeze_registry_set_item(item) for item in sorted(value, key=_registry_value_sort_key))
    return _registry_hashable_unavailable("registry_set_value_unavailable", value)


def freeze_registry_value(value: object) -> object:
    """Return a recursively immutable detection registry value with canonical mapping order."""
    items = no_hook_mapping_items(value)
    if items is not None:
        out: dict[str, object] = {}
        keyed: list[tuple[str, int, str, object, object]] = []
        for index, (raw_key, raw_item) in enumerate(items):
            key_text, key_reason = no_hook_json_key(raw_key, index, prefix="registry_key")
            keyed.append((key_text, index, key_reason, raw_key, raw_item))
        for raw_key_text, index, key_reason, raw_key, raw_item in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = no_hook_duplicate_key(key_text, index)
            if key_reason:
                out[key_text] = _registry_unavailable_record(key_reason, raw_key)
            else:
                out[key_text] = freeze_registry_value(raw_item)
        return MappingProxyType(out)
    if isinstance(value, Mapping):
        return _registry_unavailable_record("detection_registry_mapping_unavailable", value)
    if type(value) in (set, frozenset):
        return frozenset(_freeze_registry_set_item(item) for item in sorted(value, key=_registry_value_sort_key))
    if type(value) in (list, tuple):
        return tuple(freeze_registry_value(item) for item in value)
    if value is None or type(value) in (bool, int, float, str, bytes):
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) in (bytearray, memoryview):
        return bytes(value)
    return _registry_unavailable_record("detection_registry_value_unavailable", value)


__all__ = ("freeze_registry_value",)
