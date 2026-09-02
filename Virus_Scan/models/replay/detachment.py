"""Deterministic parent-replay payload detachment helpers.

Replay learning consumes worker result dictionaries after worker processes finish.
This module owns safe, deterministic detachment from caller-owned containers so
learning and runtime replay never retain mutable worker result structures.
"""
from __future__ import annotations

from collections.abc import Mapping
import math

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name

_MISSING = object()
_DICT_ITEM_METHODS = (("__iter__", dict.__iter__), ("keys", dict.keys), ("items", dict.items), ("values", dict.values))


def safe_replay_text(value: object) -> str:
    """Return replay payload text without invoking caller-owned hooks."""
    text, reason = no_hook_text(value, missing_reason="", unsupported_reason="unsupported_replay_payload_text")
    return text if reason == "" else ""


def _dict_owned_items(mapping: object) -> tuple[tuple[object, object], ...] | None:
    if type(mapping) is dict:
        return tuple(dict.items(mapping))
    if not isinstance(mapping, dict):
        return None
    mapping_type = type(mapping)
    try:
        owns_iteration = all(type.__getattribute__(mapping_type, name) is owner for name, owner in _DICT_ITEM_METHODS)
    except (AttributeError, TypeError):
        return no_hook_mapping_items(mapping)
    return tuple(dict.items(mapping)) if owns_iteration else no_hook_mapping_items(mapping)

def _replay_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    items = _dict_owned_items(value)
    return items if items is not None else no_hook_mapping_items(value)

def _replay_mapping_get(value: object, key: str, default: object = None) -> object:
    items = _replay_mapping_items(value)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__eq__(item_key, key) is True:
            return item_value
    return default

def _replay_error(field: object, reason: object) -> str:
    field_text = safe_replay_text(field)
    reason_text = safe_replay_text(reason)
    field_text = "replay_payload" if field_text == "" else field_text
    reason_text = "unsupported_replay_payload" if reason_text == "" else reason_text
    return field_text + ":" + reason_text


def finite_replay_score(value: object) -> tuple[float, bool, str | None]:
    """Return a finite parent-replay score or explicit unavailable metadata."""
    candidate = 0.0 if value is None else value
    if type(candidate) is bool:
        return 0.0, True, "non_numeric_replay_score"
    if type(candidate) is int:
        score = float(candidate)
    elif type(candidate) is float:
        score = candidate
    elif isinstance(candidate, str):
        try:
            score = float(str.__str__(candidate).strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return 0.0, True, "non_numeric_replay_score"
    elif type(candidate) is bytes:
        try:
            score = float(bytes.decode(candidate, "utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return 0.0, True, "non_numeric_replay_score"
    elif type(candidate) is bytearray:
        try:
            score = float(bytearray.decode(candidate, "utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return 0.0, True, "non_numeric_replay_score"
    else:
        return 0.0, True, "non_numeric_replay_score"
    if not math.isfinite(score):
        return 0.0, True, "non_finite_replay_score"
    return score, False, None

def replay_payload_key_order(key: object) -> str:
    text = safe_replay_text(key)
    if text != "":
        return text
    return "<" + no_hook_type_name(key) + ">"


def safe_replay_payload_key(key: object, index: int = 0) -> str:
    text = replay_payload_key_order(key)
    if text.startswith("<") and text.endswith(">"):
        return text + "#" + int.__str__(index)
    return text


def unsupported_replay_payload_value(value: object) -> dict[str, object]:
    return {
        "value": None,
        "unavailable_reason": "unsupported_replay_payload_value",
        "value_type": no_hook_type_name(value),
    }


def _is_replay_mapping(value: object) -> bool:
    return _replay_mapping_items(value) is not None


def _is_replay_sequence(value: object) -> bool:
    return type(value) in (list, tuple, set, frozenset)


def _ordered_replay_sequence(value: object) -> tuple[object, ...]:
    if type(value) is tuple:
        return value
    if type(value) is list:
        return tuple(value)
    if type(value) in (set, frozenset):
        return tuple(sorted(value, key=replay_payload_key_order))
    return ()

def detach_replay_payload_value(value: object) -> object:
    """Detach replay payload fields from caller-owned worker results."""
    if _is_replay_mapping(value):
        items = _replay_mapping_items(value)
        if items is None:
            return {
                "value": None,
                "unavailable_reason": "unreadable_replay_payload_mapping_keys",
                "value_type": no_hook_type_name(value),
            }
        out: dict[str, object] = {}
        for index, (key, child) in enumerate(sorted(items, key=lambda item: replay_payload_key_order(item[0]))):
            key_text = safe_replay_payload_key(key, index)
            if key_text in out:
                key_text = key_text + "#" + int.__str__(index)
            out[key_text] = detach_replay_payload_value(child)
        return out
    if isinstance(value, Mapping):
        return {
            "value": None,
            "unavailable_reason": "unreadable_replay_payload_mapping_keys",
            "value_type": no_hook_type_name(value),
        }
    if type(value) in (list, tuple):
        return [detach_replay_payload_value(v) for v in value]
    if type(value) in (set, frozenset):
        detached = [detach_replay_payload_value(v) for v in _ordered_replay_sequence(value)]
        return sorted(detached, key=replay_payload_key_order)
    if isinstance(value, str):
        return safe_replay_text(value)
    if value is None or type(value) in (int, bool):
        return value
    if type(value) is float:
        if math.isfinite(value):
            return value
        return {
            "value": None,
            "unavailable_reason": "non_finite_replay_payload_value",
            "value_type": no_hook_type_name(value),
        }
    text = safe_replay_text(value)
    if text != "":
        return text
    return unsupported_replay_payload_value(value)

def detach_replay_payload_sequence(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or type(value) is bytearray:
        return [detach_replay_payload_value(value)]
    if not _is_replay_sequence(value):
        return [{
            "value": None,
            "unavailable_reason": "unsupported_replay_payload_sequence",
            "value_type": no_hook_type_name(value),
        }]
    return [detach_replay_payload_value(item) for item in _ordered_replay_sequence(value)]


def replay_sequence_and_errors(value: object, field: str) -> tuple[list[object], list[str]]:
    seq = detach_replay_payload_sequence(value)
    errors: list[str] = []
    clean: list[object] = []
    for item in seq:
        reason = _replay_mapping_get(item, "unavailable_reason", _MISSING)
        if reason is not _MISSING:
            errors.append(_replay_error(field, reason))
            continue
        clean.append(item)
    return clean, errors


def detach_replay_payload_list_with_errors(
    value: object,
    field: str,
    *,
    required_sequence: bool = False,
) -> tuple[list[object], list[str]]:
    if value is None:
        return [], []
    if not _is_replay_sequence(value):
        if required_sequence:
            return [], [_replay_error(field, "unsupported_replay_payload_sequence")]
        return [], []
    detached = [detach_replay_payload_value(v) for v in _ordered_replay_sequence(value)]
    errors: list[str] = []
    clean: list[object] = []
    for item in detached:
        reason = _replay_mapping_get(item, "unavailable_reason", _MISSING)
        if reason is not _MISSING:
            errors.append(_replay_error(field, reason))
            continue
        clean.append(item)
    return clean, errors


def detach_replay_payload_mapping_with_errors(
    value: object,
    field: str,
    *,
    required_mapping: bool = False,
) -> tuple[dict[str, object], list[str]]:
    if value is None:
        return {}, []
    if not _is_replay_mapping(value):
        if required_mapping:
            return {}, [_replay_error(field, "unsupported_replay_payload_mapping")]
        return {}, []
    detached = detach_replay_payload_mapping(value)
    reason = _replay_mapping_get(detached, "unavailable_reason", _MISSING)
    if reason is not _MISSING:
        return {}, [_replay_error(field, reason)]
    if isinstance(detached, dict):
        return detached, []
    return {}, [_replay_error(field, "unsupported_replay_payload_mapping")]
def truthy_replay_sequence(value: object) -> list[object]:
    return replay_sequence_and_errors(value, "sequence")[0]
def detach_replay_payload_list(value: object) -> list[object]:
    return [detach_replay_payload_value(v) for v in _ordered_replay_sequence(value)] if _is_replay_sequence(value) else []
def detach_replay_payload_mapping(value: object) -> object:
    if _is_replay_mapping(value):
        return detach_replay_payload_value(value)
    if value is None:
        return {}
    return {
        "value": None,
        "unavailable_reason": "unsupported_replay_payload_mapping",
        "value_type": no_hook_type_name(value),
        "replay_record_required": True,
        "final_json_must_record": True,
    }
__all__ = ("detach_replay_payload_list", "detach_replay_payload_list_with_errors", "detach_replay_payload_mapping", "detach_replay_payload_mapping_with_errors", "detach_replay_payload_value", "finite_replay_score", "replay_sequence_and_errors", "safe_replay_text")
