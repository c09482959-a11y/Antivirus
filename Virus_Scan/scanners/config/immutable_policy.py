"""Canonical immutable scanner policy value boundaries.

Scanner policy snapshots may be loaded through validators or constructed
explicitly in tests and bounded scanner modules.  This module owns the single
recursive freeze operation and direct-constructor primitive coercions so frozen
dataclasses cannot retain caller-owned objects or invoke caller-owned hooks.
"""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_json_sort_key, no_hook_mapping_items, no_hook_type_name

_POLICY_MAPPING_TYPE: type = type(MappingProxyType({}))
def _policy_default_int(default: int = 0) -> int:
    if type(default) is bool:
        return 1 if default else 0
    if type(default) is int:
        return default
    return 0


def _policy_default_float(default: float = 0.0) -> float:
    if type(default) is bool:
        return 1.0 if default else 0.0
    if type(default) is int:
        return default + 0.0
    if type(default) is float:
        return default
    return 0.0


def policy_int(value: object, *, default: int = 0) -> int:
    """Preserve exact primitive ``int(value or default)`` behavior safely."""
    fallback = _policy_default_int(default)
    if value is None:
        return fallback
    if type(value) is bool:
        return 1 if value else fallback
    if type(value) is int:
        return value if value != 0 else fallback
    if type(value) is float:
        if value == 0.0:
            return fallback
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return fallback
    if type(value) is str:
        text = str.__str__(value)
        if text == "":
            return fallback
        try:
            return int(text)
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return fallback
    if type(value) is bytes:
        if not value:
            return fallback
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return fallback
    if type(value) is bytearray:
        if not value:
            return fallback
        try:
            return int(bytes(value))
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return fallback
    return fallback


def policy_float(value: object, *, default: float = 0.0) -> float:
    """Preserve exact primitive ``float(value or default)`` behavior safely."""
    fallback = _policy_default_float(default)
    if value is None:
        return fallback
    if type(value) is bool:
        return 1.0 if value else fallback
    if type(value) is int:
        return (value + 0.0) if value != 0 else fallback
    if type(value) is float:
        return value if value != 0.0 else fallback
    if type(value) is str:
        text = str.__str__(value)
        if text == "":
            return fallback
        try:
            return float(text)
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return fallback
    if type(value) is bytes:
        if not value:
            return fallback
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return fallback
    if type(value) is bytearray:
        if not value:
            return fallback
        try:
            return float(bytes(value))
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return fallback
    return fallback


def policy_text(value: object, *, default: str = "") -> str:
    """Preserve exact primitive ``str(value or default)`` behavior safely."""
    fallback = str.__str__(default) if type(default) is str else ""
    if value is None:
        return fallback
    if type(value) is str:
        text = str.__str__(value)
        return text or fallback
    if type(value) is bool:
        return "True" if value else fallback
    if type(value) is int:
        return int.__str__(value) if value != 0 else fallback
    if type(value) is float:
        return float.__str__(value) if value != 0.0 else fallback
    if type(value) is bytes:
        return bytes.__str__(value) if value else fallback
    if type(value) is bytearray:
        return bytearray.__str__(value) if value else fallback
    return fallback


def policy_bool(value: object, *, default: bool = False) -> bool:
    """Preserve exact primitive ``bool(value)`` behavior safely."""
    fallback = default if type(default) is bool else False
    if value is None:
        return False
    if type(value) in (bool, int, float, str, bytes, bytearray, tuple, list, set, frozenset, dict):
        return bool(value)
    return fallback


def _policy_scalar_text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    if type(value) is bool:
        return "True" if value else "False"
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value)
    if type(value) is bytes:
        return bytes.__str__(value)
    if type(value) is bytearray:
        return bytearray.__str__(value)
    return "unsupported_scanner_policy_value:" + no_hook_type_name(value)


def _policy_sequence_items(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) in (tuple, list):
        return tuple(value)
    if type(value) in (set, frozenset):
        return tuple(sorted(value, key=lambda item: (_policy_scalar_text(item), no_hook_json_sort_key(_policy_scalar_text(item)))))
    return ()


def policy_text_tuple(value: object) -> tuple[str, ...]:
    return tuple(_policy_scalar_text(item) for item in _policy_sequence_items(value))


def policy_text_frozenset(value: object) -> frozenset[str]:
    return frozenset(_policy_scalar_text(item) for item in _policy_sequence_items(value))


def policy_bytes_tuple(value: object) -> tuple[bytes, ...]:
    out: list[bytes] = []
    for item in _policy_sequence_items(value):
        if type(item) is bytes:
            out.append(item)
        elif type(item) is bytearray:
            out.append(bytes(item))
        else:
            out.append(("unsupported_scanner_policy_bytes:" + no_hook_type_name(item)).encode("ascii", "replace"))
    return tuple(out)


def policy_string_pairs(value: object) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for item in _policy_sequence_items(value):
        if type(item) in (tuple, list) and len(item) >= 2:
            out.append((_policy_scalar_text(item[0]), _policy_scalar_text(item[1])))
        else:
            out.append(("unsupported_scanner_policy_pair", no_hook_type_name(item)))
    return tuple(out)


def policy_group_keywords(value: object) -> tuple[tuple[str, tuple[str, ...]], ...]:
    out: list[tuple[str, tuple[str, ...]]] = []
    for item in _policy_sequence_items(value):
        if type(item) in (tuple, list) and len(item) >= 2:
            out.append((_policy_scalar_text(item[0]), policy_text_tuple(item[1])))
        else:
            out.append(("unsupported_scanner_policy_group", (no_hook_type_name(item),)))
    return tuple(out)


def _policy_mapping_key(key: object, index: int) -> str:
    text = _policy_scalar_text(key)
    if text == "":
        text = "empty_scanner_policy_key_" + int.__str__(index)
    return text


def _policy_unsupported_value(value: object) -> MappingProxyType:
    return MappingProxyType({
        "value": None,
        "unavailable_reason": "unsupported_scanner_policy_value",
        "value_type": no_hook_type_name(value),
    })


def freeze_policy_contract_value(value: object) -> object:
    """Recursively detach and freeze scanner policy payload containers."""
    items = no_hook_mapping_items(value)
    if items is not None:
        out: dict[str, object] = {}
        keyed = tuple((_policy_mapping_key(key, index), index, item) for index, (key, item) in enumerate(items))
        for key_text, index, item in sorted(keyed, key=lambda row: (row[0], row[1])):
            unique_key = key_text
            if unique_key in out:
                unique_key = str.__add__(str.__add__(unique_key, "#"), int.__str__(index))
            out[unique_key] = freeze_policy_contract_value(item)
        return MappingProxyType(out)
    if type(value) is _POLICY_MAPPING_TYPE:
        return _policy_unsupported_value(value)
    if type(value) is tuple:
        return tuple(freeze_policy_contract_value(item) for item in value)
    if type(value) is list:
        frozen_items = tuple(freeze_policy_contract_value(item) for item in value)
        try:
            return frozenset(frozen_items)
        except TypeError:
            return frozen_items
    if type(value) in (set, frozenset):
        return frozenset(freeze_policy_contract_value(item) for item in value)
    if value is None or type(value) in (bool, int, float, str, bytes):
        return value
    if type(value) is bytearray:
        return bytes(value)
    return _policy_unsupported_value(value)


__all__ = (
    "freeze_policy_contract_value",
    "policy_bool",
    "policy_bytes_tuple",
    "policy_float",
    "policy_group_keywords",
    "policy_int",
    "policy_string_pairs",
    "policy_text",
    "policy_text_frozenset",
    "policy_text_tuple",
)
