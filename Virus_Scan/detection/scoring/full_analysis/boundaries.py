"""Public full-analysis scoring boundary coercion helpers.

Full-analysis scoring consumes model evidence, profile context, and runtime scan
observations. Public callers may pass mutable or hostile containers, so these
helpers detach inputs without asking caller-owned objects for truthiness,
iteration, mapping methods, string conversion, or numeric conversion. Unsupported
external objects are represented as explicit unavailable evidence owned by the
full-analysis detection layer.
"""

from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_json_key,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_plain_instance_dict,
    no_hook_text,
    no_hook_type_name,
)

_MAPPING_PROXY_TYPE: type[object] = type(MappingProxyType({}))
_NO_ITEMS = None


def _indexed_key(key_text: str, index: int) -> str:
    return key_text + str.__str__("#") + int.__str__(index)


def _full_analysis_unavailable(reason: str, value: object) -> dict[str, object]:
    """Return explicit full-analysis evidence without stringifying ``value``."""
    return {
        "degraded": True,
        "unavailable_reason": reason,
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def _plain_backing_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return _NO_ITEMS
    for field_name in ("_values", "_data"):
        backing = dict.get(data, field_name)
        if type(backing) is dict:
            items = no_hook_mapping_items(backing)
            return items if items is not None else _NO_ITEMS
    return _NO_ITEMS


def _full_analysis_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is not None:
        return items
    return _plain_backing_mapping_items(value)


def _plain_backing_sequence_items(value: object) -> tuple[object, ...] | None:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return _NO_ITEMS
    backing: object = dict.get(data, "_values")
    if type(backing) is tuple:
        return backing
    if type(backing) is list:
        return tuple(backing)
    if type(backing) is set:
        return tuple(sorted(backing, key=no_hook_json_sort_key))
    if type(backing) is frozenset:
        return tuple(sorted(backing, key=no_hook_json_sort_key))
    return _NO_ITEMS


def _safe_sequence_subclass_items(value: object) -> tuple[object, ...] | None:
    value_type = type(value)
    try:
        if isinstance(value, list):
            safe = (
                type.__getattribute__(value_type, "__iter__") is list.__iter__
                and type.__getattribute__(value_type, "__len__") is list.__len__
            )
            return tuple(list.__iter__(value)) if safe else _NO_ITEMS
        if isinstance(value, tuple):
            safe = (
                type.__getattribute__(value_type, "__iter__") is tuple.__iter__
                and type.__getattribute__(value_type, "__len__") is tuple.__len__
            )
            return tuple(tuple.__iter__(value)) if safe else _NO_ITEMS
        if isinstance(value, set):
            safe = (
                type.__getattribute__(value_type, "__iter__") is set.__iter__
                and type.__getattribute__(value_type, "__len__") is set.__len__
            )
            return tuple(sorted(set.__iter__(value), key=no_hook_json_sort_key)) if safe else _NO_ITEMS
        if isinstance(value, frozenset):
            safe = (
                type.__getattribute__(value_type, "__iter__") is frozenset.__iter__
                and type.__getattribute__(value_type, "__len__") is frozenset.__len__
            )
            return tuple(sorted(frozenset.__iter__(value), key=no_hook_json_sort_key)) if safe else _NO_ITEMS
    except (TypeError, ValueError, RuntimeError, OSError):
        return _NO_ITEMS
    return _NO_ITEMS


def _full_analysis_sequence_items(value: object) -> tuple[object, ...] | None:
    if value is None:
        return ()
    if type(value) in (str, bytes, bytearray, int, float, bool):
        return (value,)
    if no_hook_mapping_items(value) is not None:
        return (value,)
    if type(value) is tuple:
        return tuple(value)
    if type(value) is list:
        return tuple(value)
    if type(value) is set:
        return tuple(sorted(value, key=no_hook_json_sort_key))
    if type(value) is frozenset:
        return tuple(sorted(value, key=no_hook_json_sort_key))
    subclass_items = _safe_sequence_subclass_items(value)
    if subclass_items is not None:
        return subclass_items
    return _plain_backing_sequence_items(value)



def _full_analysis_materialize_value(value: object, *, depth: int = 0) -> object:
    if depth > 12:
        return _full_analysis_unavailable("full_analysis_depth_limit_exceeded", value)
    mapping_items = _full_analysis_mapping_items(value)
    if mapping_items is not None:
        return _materialize_mapping_items(mapping_items, source=value, depth=depth + 1)
    sequence_items = _full_analysis_sequence_items(value)
    if sequence_items is not None and not (type(value) in (str, bytes, bytearray, int, float, bool) or value is None):
        return [_full_analysis_materialize_value(item, depth=depth + 1) for item in sequence_items]
    return no_hook_materialize(value, depth=depth, reason_prefix="full_analysis")

def _materialize_mapping_items(items: tuple[tuple[object, object], ...], *, source: object, depth: int = 0) -> dict[str, object]:
    del source  # Explicitly unused contract parameters.
    out: dict[str, object] = {}
    keyed: list[tuple[str, int, object, object, str]] = []
    for index, (raw_key, raw_value) in enumerate(items):
        key_text, key_reason = no_hook_json_key(raw_key, index, prefix="full_analysis_key")
        keyed.append((key_text, index, raw_key, raw_value, key_reason))
    for raw_key_text, index, raw_key, raw_value, key_reason in sorted(keyed, key=lambda row: (row[0], row[1])):
        key_text = raw_key_text
        if key_text in out:
            key_text = _indexed_key(key_text, index)
        if key_reason:
            out[key_text] = _full_analysis_unavailable(key_reason, raw_key)
        else:
            out[key_text] = _full_analysis_materialize_value(raw_value, depth=depth + 1)
    return out


def _materialized_mapping_or_unavailable(value: object, *, reason: str) -> dict[str, object]:
    items = _full_analysis_mapping_items(value)
    if items is None:
        return _full_analysis_unavailable(reason, value)
    return _materialize_mapping_items(items, source=value)


def _exact_key_equal(left: object, right: object) -> bool:
    """Compare exact builtin mapping keys without caller-owned equality hooks."""
    if type(left) is not type(right):
        return False
    if type(left) is str:
        return str.__eq__(left, right)
    if type(left) is bool:
        return bool.__eq__(left, right)
    if type(left) is int:
        return int.__eq__(left, right)
    if type(left) is float:
        return float.__eq__(left, right)
    return left is None


def full_analysis_sequence(value: object) -> tuple[object, ...]:
    """Freeze exact builtin sequence-like public input without caller hooks."""
    if value is None:
        return ()
    if _full_analysis_mapping_items(value) is not None:
        return (full_analysis_mapping(value),)
    items = _full_analysis_sequence_items(value)
    if items is not None:
        return tuple(_full_analysis_materialize_value(item) for item in items)
    return (_full_analysis_unavailable("full_analysis_iterable_rejected", value),)


def full_analysis_mapping(value: object) -> dict[str, object]:
    """Detach exact owned mappings without caller-owned mapping methods."""
    if value is None:
        return {}
    if _full_analysis_mapping_items(value) is None:
        return _full_analysis_unavailable("full_analysis_mapping_rejected", value)
    return _materialized_mapping_or_unavailable(value, reason="full_analysis_mapping_unavailable")


def full_analysis_mapping_get(mapping: object, key: object, default: object = None) -> object:
    """Read an exact owned mapping field without invoking mapping hooks."""
    if mapping is None:
        return default
    items = _full_analysis_mapping_items(mapping)
    if items is None:
        return default
    for item_key, item_value in items:
        if _exact_key_equal(item_key, key):
            return item_value
    return default


def full_analysis_mapping_field(mapping: object, key: object) -> dict[str, object]:
    """Read and detach a nested owned mapping field."""
    return full_analysis_mapping(full_analysis_mapping_get(mapping, key, {}))


def full_analysis_first_mapping(mapping: object, *keys: object) -> dict[str, object]:
    """Return the first nested field that is an exact owned mapping."""
    if _full_analysis_mapping_items(mapping) is None:
        return {}
    for key in keys:
        candidate = full_analysis_mapping_get(mapping, key, None)
        if _full_analysis_mapping_items(candidate) is not None:
            detached = full_analysis_mapping(candidate)
            if len(detached) > 0:
                return detached
    return {}


def full_analysis_text(value: object, *, default: str = "") -> str:
    """Coerce text from exact safe primitives without caller string hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="full_analysis_text_missing",
        unsupported_reason="full_analysis_text_rejected",
    )
    if reason:
        return default
    stripped = str.__str__(text).strip()
    return stripped if stripped != "" else default


def full_analysis_float(value: object, *, default: float = 0.0) -> float:
    """Coerce a bounded finite float without caller numeric hooks."""
    numeric, _reason = no_hook_finite_float(
        value,
        default=default,
        reason="full_analysis_numeric_rejected",
        non_finite_reason="full_analysis_non_finite_number",
    )
    return numeric


def full_analysis_nonempty_mapping(value: object) -> bool:
    """Check owned mapping content without invoking caller-owned bool/len."""
    items = _full_analysis_mapping_items(value)
    if items is None:
        return False
    return len(items) > 0


__all__ = (
    "full_analysis_first_mapping",
    "full_analysis_float",
    "full_analysis_mapping",
    "full_analysis_mapping_field",
    "full_analysis_mapping_get",
    "full_analysis_nonempty_mapping",
    "full_analysis_sequence",
    "full_analysis_text",
)
