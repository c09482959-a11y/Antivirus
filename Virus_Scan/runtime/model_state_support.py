"""No-hook runtime model state support primitives.

This module owns deterministic mapping, text, count, and transition-key
materialization helpers for :mod:`Virus_Scan.runtime.model_state` so the public
runtime model API remains a bounded mutation owner.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import math
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.markov_learning import (
    MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
    MARKOV_EVENT_KEY_TYPE,
    MARKOV_EVENT_VOCABULARY_KEY_TYPE,
    MARKOV_STAGE_KEY_TYPE,
    MARKOV_STAGE_VOCABULARY_KEY_TYPE,
)
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_failure,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_type_name,
)

_RUNTIME_MUTABLE_MAPPING_TYPES = (dict, defaultdict, Counter)

def _runtime_model_type_attr(value: object, name: str, default: str = "unknown") -> str:
    try:
        attr = type.__getattribute__(type(value), name)
    except (AttributeError, TypeError):
        return default
    if type(attr) is str:
        return str.__str__(attr)
    return default

def _is_runtime_mutable_mapping_storage(value: object) -> bool:
    """Return whether runtime may own and mutate this exact mapping type."""
    return isinstance(value, dict)

def _runtime_model_mapping_items_unavailable(value: object) -> tuple[tuple[str, MappingProxyType], ...]:
    return ((
        "runtime_model_mapping_items_unavailable",
        MappingProxyType(no_hook_failure("runtime_model_mapping_items_unavailable", value)),
    ),)

def _runtime_model_owned_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    """Return owned mapping items without invoking caller-owned mapping hooks."""
    if type(value) in _RUNTIME_MUTABLE_MAPPING_TYPES:
        try:
            owned_items = dict.items(value)
            return tuple(owned_items)
        except RECOVERABLE_RUNTIME_ERRORS:
            return _runtime_model_mapping_items_unavailable(value)
    return no_hook_mapping_items(value)

def _runtime_model_join_text(*parts: object) -> str:
    text_parts: list[str] = []
    for part in parts:
        if type(part) is str:
            text_parts.append(str.__str__(part))
        elif type(part) is int and type(part) is not bool:
            text_parts.append(int.__str__(part))
        else:
            text_parts.append(_runtime_model_display_text(part))
    return "".join(text_parts)

def _runtime_model_dot_path(prefix: str, suffix: object) -> str:
    return _runtime_model_join_text(prefix, ".", suffix)

def _runtime_model_index_path(prefix: str, index: int, suffix: str = "") -> str:
    return _runtime_model_join_text(prefix, "[", index, "]", suffix)

def _runtime_model_is_owned_mapping(value: object) -> bool:
    return _runtime_model_owned_mapping_items(value) is not None

def _runtime_model_owned_mapping_get(mapping: object, key: object, default: object = None) -> object:
    """Read exact owned mapping keys without invoking arbitrary mapping methods."""
    items = _runtime_model_owned_mapping_items(mapping)
    if items is None:
        return default
    if type(key) is str:
        wanted = str.__str__(key)
        for raw_key, raw_value in items:
            if type(raw_key) is str and str.__eq__(str.__str__(raw_key), wanted):
                return raw_value
        return default
    if isinstance(mapping, dict):
        try:
            return dict.get(mapping, key, default)
        except RECOVERABLE_RUNTIME_ERRORS:
            return default
    for raw_key, raw_value in items:
        if raw_key is key:
            return raw_value
    return default

def _runtime_model_matches_expected(value: object, expected: object) -> bool:
    """Validate persisted section shape without arbitrary mapping hooks."""
    if expected is Mapping:
        return _runtime_model_is_owned_mapping(value)
    if type(expected) is tuple and Mapping in expected:
        if _runtime_model_is_owned_mapping(value):
            return True
        remaining = tuple(item for item in expected if item is not Mapping)
        return type(value) in remaining
    if type(expected) is tuple:
        return type(value) in expected
    return type(value) is expected

def _runtime_model_count_with_reason(value: object, default: int = 0) -> tuple[int, str]:
    """Materialize a non-negative finite runtime model count and reason.

    Runtime snapshots are replay-affecting model evidence.  Corrupt persisted
    counts are still sanitized to preserve no-crash behavior, but the caller can
    now publish explicit unavailable/degraded evidence instead of silently
    collapsing NaN/Infinity/negative/non-numeric state into a clean zero.
    """
    if value is None:
        return int(default), ""
    if isinstance(value, str) and _runtime_model_exact_str(value) == "":
        return int(default), ""
    if type(value) is bool:
        return int(default), "non_numeric_runtime_model_count"
    if type(value) is int:
        numeric = float(value)
    elif type(value) is float:
        numeric = value
    elif isinstance(value, str):
        try:
            numeric = float(_runtime_model_exact_str(value).strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return int(default), "non_numeric_runtime_model_count"
    elif type(value) in (bytes, bytearray):
        try:
            numeric = float(bytes(value).decode("utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return int(default), "non_numeric_runtime_model_count"
    else:
        return int(default), "non_numeric_runtime_model_count"
    if not math.isfinite(numeric):
        return int(default), "non_finite_runtime_model_count"
    if numeric < 0.0:
        return int(default), "negative_runtime_model_count"
    if not numeric.is_integer():
        return int(default), "fractional_runtime_model_count"
    return int(numeric), ""

def _runtime_model_count(value: object, default: int = 0) -> int:
    """Materialize a non-negative finite runtime model count."""
    count, _reason = _runtime_model_count_with_reason(value, default)
    return int(count)

def _immutable_counter_snapshot(counter: object) -> Mapping[object, int]:
    """Return a read-only deterministic counter snapshot detached from runtime state.

    Runtime counters are replay-affecting learned model evidence.  Empty target
    identities and non-positive/sanitized counts may be injected through stale
    in-memory state or older callers; they must not become support/vocabulary
    evidence for Markov probability APIs.
    """
    if _runtime_model_owned_mapping_items(counter) is None:
        return MappingProxyType({})
    materialized = {}
    for k, v in _sorted_counter_items(counter):
        key_text = _runtime_model_nonempty_text(k)
        count = _runtime_model_count(v)
        if not key_text or count <= 0:
            continue
        materialized[key_text] = count
    return MappingProxyType(materialized)

def _runtime_model_exact_str(value: str) -> str:
    """Detach a string or string subclass into an exact built-in string."""
    return str.__str__(value)

def _runtime_model_display_text(value: object) -> str:
    """Return deterministic evidence text without trusting hostile __str__/__repr__."""
    if isinstance(value, str):
        return _runtime_model_exact_str(value)
    if type(value) is bytes:
        return value.decode("utf-8", "replace")
    if type(value) is bytearray:
        return bytes(value).decode("utf-8", "replace")
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float and math.isfinite(value):
        return float.__str__(value)
    type_name = _runtime_model_type_attr(value, "__qualname__", _runtime_model_type_attr(value, "__name__"))
    module_name = _runtime_model_type_attr(value, "__module__", "builtins")
    return _runtime_model_join_text("<unrepresentable:", module_name, ".", type_name, ">")

def _runtime_model_identity_text(value: object) -> tuple[str, str]:
    """Return persisted identity text plus reason when text is unavailable."""
    if value is None:
        return "", "missing_runtime_model_identity"
    if isinstance(value, str):
        return str.strip(_runtime_model_exact_str(value)), ""
    text = _runtime_model_display_text(value)
    if text.startswith("<unrepresentable:"):
        return "", "unreadable_runtime_model_identity"
    return str.strip(_runtime_model_exact_str(text)), ""

def _runtime_model_mapping_get(mapping: object, key: object, default: object = None) -> object:
    """Read an owned mapping key without invoking caller-owned mapping methods."""
    return _runtime_model_owned_mapping_get(mapping, key, default)

def _runtime_model_sort_key(value: object) -> str:
    """Stable no-hook sort key for runtime model values."""
    return no_hook_json_sort_key(_runtime_model_json_sort_value(value))

def _runtime_model_json_sort_value(value: object) -> object:
    if value is None or type(value) in (bool, int):
        return value
    if isinstance(value, str):
        return _runtime_model_exact_str(value)
    if type(value) is float:
        return value if math.isfinite(value) else {"unavailable_reason": "non_finite_runtime_model_sort_value"}
    if type(value) in (bytes, bytearray):
        return _runtime_model_display_text(value)
    if type(value) in (tuple, list):
        return tuple(_runtime_model_json_sort_value(item) for item in value)
    if type(value) in (set, frozenset):
        return tuple(sorted((_runtime_model_json_sort_value(item) for item in value), key=no_hook_json_sort_key))
    items = _runtime_model_owned_mapping_items(value)
    if items is not None:
        return tuple(
            sorted(
                ((_runtime_model_json_sort_value(key), _runtime_model_json_sort_value(item)) for key, item in items),
                key=no_hook_json_sort_key,
            )
        )
    return {"unavailable_reason": "non_materializable_runtime_model_sort_value", "value_type": no_hook_type_name(value)}

def _runtime_model_items(value: object) -> tuple[tuple[object, object], ...]:
    """Return mapping items without trusting hostile mapping implementations."""
    items = _runtime_model_owned_mapping_items(value)
    return items if items is not None else ()

def _runtime_model_sorted_items(value: object) -> tuple[tuple[object, object], ...]:
    return tuple(sorted(_runtime_model_items(value), key=lambda item: _runtime_model_sort_key(item[0])))

def _runtime_model_mapping_nonempty(value: object) -> bool:
    return bool(_runtime_model_items(value))

def _runtime_model_keys(value: object) -> tuple[object, ...]:
    items = _runtime_model_owned_mapping_items(value)
    if items is None:
        return ()
    return tuple(key for key, _value in items)

def _runtime_model_sequence_values(value: object) -> tuple[object, ...]:
    """Return a detached tuple only from exact owned sequence containers."""
    if value is None or isinstance(value, str) or type(value) in (bytes, bytearray):
        return ()
    if _runtime_model_owned_mapping_items(value) is not None:
        return ()
    if type(value) in (tuple, list):
        return tuple(value)
    if type(value) in (set, frozenset):
        return tuple(sorted(value, key=_runtime_model_sort_key))
    return ()

def _sorted_counter_items(counter: object) -> object:
    if _runtime_model_owned_mapping_items(counter) is None:
        return ()
    return _runtime_model_sorted_items(counter)

def _runtime_transition_key_error(key: object) -> str:
    """Return why a live runtime transition key is not learned Markov evidence."""
    if type(key) is not tuple or len(key) != 2:
        return "invalid_runtime_transition_key"
    left, right = key
    key_type = _runtime_model_nonempty_text(left)
    if key_type in {MARKOV_EVENT_KEY_TYPE, MARKOV_STAGE_KEY_TYPE}:
        if type(right) is not tuple or len(right) != 3:
            return "invalid_runtime_transition_key"
        parts = tuple(_runtime_model_nonempty_text(item) for item in right)
        return "" if all(parts) else "invalid_runtime_transition_key"
    if key_type in {
        MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
        MARKOV_EVENT_VOCABULARY_KEY_TYPE,
        MARKOV_STAGE_VOCABULARY_KEY_TYPE,
    }:
        return "" if _runtime_model_nonempty_text(right) else "invalid_runtime_transition_key"
    return "invalid_runtime_transition_key"

def _runtime_model_failure(path: str, reason: str, value: object = None) -> dict[str, str]:
    record = {
        "path": _runtime_model_display_text(path),
        "reason": _runtime_model_display_text(reason),
    }
    if value is not None:
        record["value"] = _runtime_model_display_text(value)
    return record

def _runtime_model_nonempty_text(value: object) -> str:
    """Return stripped text for persisted model identity keys or an empty marker."""
    text, reason = _runtime_model_identity_text(value)
    if reason:
        return ""
    return text

def _runtime_model_lower_text(value: object) -> str:
    if type(value) is str:
        return str.lower(str.__str__(value))
    return "runtime_model_text_unavailable"

def _runtime_model_expected_name(expected: object) -> str:
    def _name(item: object) -> str:
        if isinstance(item, type):
            try:
                name = type.__getattribute__(item, "__name__")
            except (AttributeError, TypeError):
                return "runtime_model_expected_name_unavailable"
            if type(name) is str:
                return _runtime_model_lower_text(name)
        return _runtime_model_lower_text(_runtime_model_display_text(item))

    if type(expected) is tuple:
        return "_or_".join(_name(item) for item in expected)
    return _name(expected)

def _runtime_model_section(source: Mapping[str, object], name: str, expected: object, failures: list[dict[str, str]], default: object) -> object:
    value = _runtime_model_mapping_get(source, name, default)
    if value is None:
        return default
    if not _runtime_model_matches_expected(value, expected):
        failures.append(_runtime_model_failure(name, _runtime_model_join_text("non_", _runtime_model_expected_name(expected), "_runtime_model_section")))
        return default
    return value

def _runtime_transition_row_error(row: Mapping[str, object]) -> str:
    """Return why a persisted transition row cannot become learned evidence."""
    row_type = _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "type", ""))
    if row_type not in {
        MARKOV_EVENT_KEY_TYPE,
        MARKOV_STAGE_KEY_TYPE,
        MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
        MARKOV_EVENT_VOCABULARY_KEY_TYPE,
        MARKOV_STAGE_VOCABULARY_KEY_TYPE,
    }:
        return "invalid_runtime_transition_type"
    target = _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "target"))
    if not target:
        return "invalid_runtime_transition_target"
    if row_type == MARKOV_EVENT_KEY_TYPE:
        fields = ("context", "previous_stage", "source_event")
        if any(
            not _runtime_model_nonempty_text(_runtime_model_mapping_get(row, field))
            for field in fields
        ):
            return "invalid_runtime_transition_key"
    elif row_type == MARKOV_STAGE_KEY_TYPE:
        fields = ("context", "previous_stage", "flow_class")
        if any(
            not _runtime_model_nonempty_text(_runtime_model_mapping_get(row, field))
            for field in fields
        ):
            return "invalid_runtime_transition_key"
    elif row_type in {
        MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
        MARKOV_EVENT_VOCABULARY_KEY_TYPE,
        MARKOV_STAGE_VOCABULARY_KEY_TYPE,
    }:
        if not _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "context")):
            return "invalid_runtime_transition_key"
    return ""
