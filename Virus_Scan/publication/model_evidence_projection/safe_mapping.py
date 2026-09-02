"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

import gc
import math
from types import MappingProxyType

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from .safe_mapping_primitives import (
    model_evidence_blank_key,
    model_evidence_child_path,
    model_evidence_duplicate_key,
    model_evidence_field_path,
    model_evidence_index_path,
    model_evidence_is_container,
    model_evidence_is_mapping,
    model_evidence_is_sequence,
    model_evidence_missing_field_reason,
    model_evidence_non_boolean_flag_reason,
    model_evidence_probability_model_name,
    model_evidence_sequence_items,
    model_evidence_type_marker,
    model_evidence_unavailable_field,
    model_evidence_unavailable_reasons_field,
    model_evidence_unavailable_repr,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_MAPPING_PROXY_TYPE: type[object] = type(MappingProxyType({}))
def _mapping_proxy_backing_dict(value: object) -> dict[object, object] | None:
    """Return the mapping-proxy backing dict without calling proxy mapping hooks."""
    backing: dict[object, object] | None = None
    if type(value) is _MAPPING_PROXY_TYPE:
        referents: list[object] = []
        try:
            referents = gc.get_referents(value)
        except RECOVERABLE_RUNTIME_ERRORS:
            referents = []
        if len(referents) == 1 and isinstance(referents[0], dict):
            backing = referents[0]
    return backing

def _owned_dict_like(value: object) -> dict[object, object] | None:
    if isinstance(value, dict):
        return value
    return _mapping_proxy_backing_dict(value)

def _owned_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    """Return mapping items without invoking caller-owned mapping hooks."""
    items: tuple[tuple[object, object], ...] | None = None
    backing = _owned_dict_like(value)
    if backing is not None:
        try:
            items = tuple(dict.items(backing))
        except RECOVERABLE_RUNTIME_ERRORS:
            items = None
    return items

def _safe_mapping_key_matches(candidate: object, expected: object) -> bool:
    if type(expected) is str:
        text, reason = safe_text_result(candidate)
        return reason == "" and text == expected
    if expected is None:
        return candidate is None
    if type(expected) in (int, float, bool):
        return type(candidate) is type(expected) and candidate == expected
    return candidate is expected

def safe_repr(value: object) -> str:
    if isinstance(value, str):
        return repr(str.__str__(value))
    if type(value) is bytes:
        return value.decode("utf-8", errors="replace")
    if type(value) is bytearray:
        return bytes(value).decode("utf-8", errors="replace")
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value)
    return model_evidence_unavailable_repr(value)

def _detached_text(value: object) -> str | None:
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) in (bytes, bytearray, memoryview):
        return bytes(value).decode("utf-8", errors="replace")
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float and math.isfinite(value):
        return float.__str__(value)
    return None

def safe_text_result(value: object, *, allow_path: bool = True, allow_attrs: bool = True) -> tuple[str, str]:
    """Return detached model-evidence text plus an explicit unavailable reason.

    Publication is the final JSON boundary for model evidence. It may detach
    exact built-in text, bytes-like values, and scalar primitives, but it must
    not call caller-owned ``__str__``, path-protocol, property, or formatting
    hooks for unsupported objects.
    """
    del allow_path, allow_attrs
    if value is None:
        return "", "missing_model_evidence_text"
    try:
        detached = _detached_text(value)
        if detached is not None:
            return detached, ""
        # Unknown objects are evidence-boundary inputs, not text providers.
        # Do not call caller-owned path, property, or string hooks here.
    except RECOVERABLE_RUNTIME_ERRORS:
        return model_evidence_type_marker(value), "unreadable_model_evidence_text"
    return model_evidence_type_marker(value), "unsupported_model_evidence_text"

def safe_str(value: object) -> str:
    """Return detached text without invoking caller-owned ``__str__`` hooks."""
    result = safe_text_result(value)
    return result[0]

def safe_text_sort_key(value: object) -> tuple[str, str, str]:
    result = safe_text_result(value)
    text = result[0]
    reason = result[1]
    if reason:
        return (model_evidence_type_marker(value), reason, "")
    return (text.lower(), text, "")

def is_explicit_empty_text(value: object) -> bool:
    """Return True only for a literal empty text value without probing caller truthiness."""
    return isinstance(value, str) and value == ""

def safe_text_present(value: object) -> bool:
    """Return whether a value has non-blank text without using ``value or ...``."""
    if value is None:
        return False
    result = safe_text_result(value)
    text = result[0]
    reason = result[1]
    return reason == '' and str.strip(text) != ''

def safe_mapping_items(value: Mapping[str, object]) -> tuple[tuple[tuple[object, object], ...], str]:
    items = _owned_mapping_items(value)
    if items is None:
        return (), "unreadable_model_evidence_mapping"
    try:
        return tuple(sorted(items, key=lambda pair: safe_text_sort_key(pair[0]))), ""
    except RECOVERABLE_RUNTIME_ERRORS:
        return (), "unreadable_model_evidence_mapping"

def safe_mapping_keys(value: Mapping[str, object]) -> tuple[tuple[object, ...], str]:
    items, reason = safe_mapping_items(value)
    if reason != "":
        return (), reason
    return tuple(key for key, _item in items), ""

def safe_mapping_find(value: Mapping[str, object], key: object, /) -> tuple[bool, bool, object]:
    items, reason = safe_mapping_items(value)
    if reason != "":
        return False, False, None
    for candidate, item in items:
        if _safe_mapping_key_matches(candidate, key):
            return True, True, item
    return True, False, None

def safe_mapping_read(value: Mapping[str, object], key: object, /) -> tuple[bool, object]:
    readable, found, item = safe_mapping_find(value, key)
    if readable and not found:
        return True, None
    return readable, item

def safe_mapping_get(value: Mapping[str, object], key: object, /, replacement: object = None) -> object:
    readable, found, item = safe_mapping_find(value, key)
    if not readable:
        return replacement
    return item if found else None

def safe_mapping_contains(value: Mapping[str, object], key: object) -> bool:
    readable, found, _item = safe_mapping_find(value, key)
    return readable and found

def mapping_readable(value: object) -> bool:
    if _owned_mapping_items(value) is None:
        return False
    key_state = safe_mapping_keys(value)
    reason = key_state[1]
    return reason == ''

def _json_mapping_key_text(key: object, index: int) -> tuple[str, str]:
    result = safe_text_result(key)
    text = result[0]
    reason = result[1]
    if reason:
        return model_evidence_type_marker(key), "unreadable_json_mapping_key"
    if text == "":
        return model_evidence_blank_key(index), "blank_json_mapping_key"
    return text, ""

def _json_owned_mapping_value(value: object) -> object:
    items, reason = safe_mapping_items(value)
    if reason:
        return {
            "unavailable_reason": reason,
            "value_type": no_hook_type_name(value),
        }
    out: dict[str, object] = {}
    for index, (key, readable_value) in enumerate(items):
        name, key_reason = _json_mapping_key_text(key, index)
        if name in out:
            name = model_evidence_duplicate_key(name, index)
        if key_reason != "":
            out[name] = {
                "value": None,
                "unavailable_reason": key_reason,
                "value_type": no_hook_type_name(key),
            }
        else:
            out[name] = json_value(readable_value)
    return out


def _json_container_value(value: object) -> object:
    if type(value) in (set, frozenset):
        items = sorted(value, key=safe_text_sort_key)
    else:
        items = model_evidence_sequence_items(value)
    return tuple(json_value(item) for item in items)


def _json_float_value(value: float) -> object:
    if math.isfinite(value):
        projected: object = value
    else:
        projected = {
            "unavailable_reason": "non_finite_model_evidence_value",
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        }
    return projected


def _json_scalar_or_text_value(value: object) -> object:
    if type(value) is float:
        projected = _json_float_value(value)
    elif isinstance(value, str):
        projected = safe_str(value)
    elif type(value) in (int, bool) or value is None:
        projected = value
    elif type(value) in (bytes, bytearray, memoryview):
        projected = safe_text_result(value)[0]
    else:
        text, reason = safe_text_result(value)
        projected = (
            {
                "value": None,
                "unavailable_reason": reason,
                "value_type": no_hook_type_name(value),
                "value_repr": safe_repr(value),
            }
            if reason
            else text
        )
    return projected


def _json_nonmapping_value(value: object) -> object:
    if model_evidence_is_mapping(value):
        projected: object = {
            "value": None,
            "unavailable_reason": "unreadable_model_evidence_mapping",
            "value_type": no_hook_type_name(value),
        }
    elif type(value) in (set, frozenset) or model_evidence_is_sequence(value):
        projected = _json_container_value(value)
    else:
        projected = _json_scalar_or_text_value(value)
    return projected


def json_value(value: object) -> object:
    if _owned_mapping_items(value) is not None:
        return _json_owned_mapping_value(value)
    return _json_nonmapping_value(value)
def mapping_at(record: Mapping[str, object], key: str) -> Mapping[str, object]:
    mapped_value = safe_mapping_get(record, key)
    return mapped_value if mapping_readable(mapped_value) else {}

__all__ = ('is_explicit_empty_text', 'json_value', 'mapping_at', 'mapping_readable', 'model_evidence_blank_key', 'model_evidence_child_path', 'model_evidence_duplicate_key', 'model_evidence_field_path', 'model_evidence_index_path', 'model_evidence_is_container', 'model_evidence_is_mapping', 'model_evidence_is_sequence', 'model_evidence_missing_field_reason', 'model_evidence_non_boolean_flag_reason', 'model_evidence_probability_model_name', 'model_evidence_sequence_items', 'model_evidence_type_marker', 'model_evidence_unavailable_field', 'model_evidence_unavailable_reasons_field', 'model_evidence_unavailable_repr', 'safe_mapping_contains', 'safe_mapping_find', 'safe_mapping_get', 'safe_mapping_items', 'safe_mapping_keys', 'safe_mapping_read', 'safe_repr', 'safe_str', 'safe_text_present', 'safe_text_result', 'safe_text_sort_key')
