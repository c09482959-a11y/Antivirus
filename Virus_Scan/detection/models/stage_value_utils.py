"""Immutable value helpers for detection stage boundaries."""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from Virus_Scan.detection.models.failure_state import failure_state_records
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_plain_instance_dict,
    no_hook_text,
    no_hook_type_name,
)

_DETECTION_RECOVERABLE_EXCEPTIONS = (TypeError, ValueError, RuntimeError, OSError)
_JSON_PRIMITIVES = (str, int, bool, type(None))


def _detection_exact_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_detection_text",
        unsupported_reason="unsupported_detection_text",
    )
    if reason:
        raise TypeError(reason)
    return text



def _plain_backing_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return None
    for field_name in ("_values", "_data"):
        backing = dict.get(data, field_name)
        if type(backing) is dict:
            return tuple(dict.items(backing))
    return None


def _safe_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    items = no_hook_mapping_items(value)
    if items is not None:
        return items
    return _plain_backing_mapping_items(value)


def _plain_backing_sequence_items(value: object) -> tuple[object, ...] | None:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return None
    backing: object = dict.get(data, "_values")
    if type(backing) is tuple:
        return backing
    if type(backing) is list:
        return tuple(backing)
    if type(backing) is set:
        return tuple(sorted(backing, key=_detection_value_sort_key))
    if type(backing) is frozenset:
        return tuple(sorted(backing, key=_detection_value_sort_key))
    return None


def _builtin_sequence_items(value: object) -> tuple[object, ...] | None:
    if type(value) is list:
        return tuple(value)
    if type(value) is tuple:
        return value
    if type(value) is set:
        return tuple(sorted(value, key=_detection_value_sort_key))
    if type(value) is frozenset:
        return tuple(sorted(value, key=_detection_value_sort_key))
    return _plain_backing_sequence_items(value)

def _detection_reason_text(reason: object, default_text: str) -> str:
    """Normalize detection evidence reasons without truth-testing caller values."""
    if reason is None:
        return default_text
    try:
        text = _detection_exact_text(reason).strip()
    except _DETECTION_RECOVERABLE_EXCEPTIONS:
        return default_text
    return text or default_text


def detection_unavailable_value(reason: str, value: object | None = None) -> Mapping[str, object]:
    """Return immutable explicit evidence for an unreadable detection boundary value."""
    value_type = no_hook_type_name(value) if value is not None else "unknown"
    return MappingProxyType({
        "degraded": True,
        "unavailable_reason": _detection_reason_text(reason, "detection_value_unavailable"),
        "value_type": value_type,
        "final_json_must_record": True,
        "replay_record_required": True,
    })


def _safe_detection_text(value: object, reason: str) -> tuple[str, Mapping[str, object] | None]:
    """Return safe text plus optional explicit unavailable evidence."""
    try:
        text = _detection_exact_text(value)
    except _DETECTION_RECOVERABLE_EXCEPTIONS:
        evidence = detection_unavailable_value(reason, value)
        return evidence["unavailable_reason"], evidence
    return text, None


def safe_detection_text(value: object, default_text: str, reason: str = "detection_text_unavailable") -> tuple[str, Mapping[str, object] | None]:
    """Normalize public detection text without raising on hostile values."""
    if value is None:
        return default_text, None
    text, evidence = _safe_detection_text(value, reason)
    if evidence is not None:
        return default_text, evidence
    text = text.strip()
    return (text or default_text), None


def detection_value_or_default(value: object, default: object) -> object:
    """Return default only for absent values without probing caller truthiness."""
    return default if value is None else value


def safe_detection_bool(
    value: object,
    *,
    default_bool: bool = False,
    reason: str = "detection_bool_unavailable",
) -> tuple[bool, Mapping[str, object] | None]:
    """Normalize booleans without executing caller-owned truthiness hooks."""
    if value is None:
        return default_bool, None
    if type(value) is bool:
        return value, None
    return default_bool, detection_unavailable_value(reason, value)


def frozen_tuple_or_empty(value: object) -> tuple[object, ...]:
    """Freeze an optional iterable without truthiness probing."""
    return frozen_tuple(detection_value_or_default(value, ()))


def freeze_mapping_or_empty(value: object) -> object:
    """Freeze an optional mapping-like value without truthiness probing."""
    return freeze_detection_value(detection_value_or_default(value, {}))


def _ordered_detection_mapping_items(
    items: tuple[tuple[object, object], ...],
) -> tuple[tuple[object, object], ...]:
    """Return the one canonical mapping order without redundant value sorting."""
    if all(type(key) is str for key, _item in items):
        return tuple(sorted(items, key=lambda pair: no_hook_json_sort_key(pair[0])))
    return tuple(sorted(
        items,
        key=lambda pair: (
            _detection_value_sort_key(pair[0]),
            _detection_value_sort_key(pair[1]),
        ),
    ))


def _freeze_detection_mapping(value: Mapping[object, object]) -> object:
    items = _safe_mapping_items(value)
    if items is None:
        return detection_unavailable_value("detection_mapping_keys_unavailable", value)
    frozen: dict[object, object] = {}
    for raw_key, raw_value in _ordered_detection_mapping_items(items):
        key = freeze_detection_value(raw_key)
        if not isinstance(key, (str, int, float, bool, type(None))):
            key = _detection_value_sort_key(key)
        try:
            frozen[key] = freeze_detection_value(raw_value)
        except _DETECTION_RECOVERABLE_EXCEPTIONS:
            replacement_key = _detection_value_sort_key(key)
            frozen[replacement_key] = detection_unavailable_value("detection_mapping_item_unavailable", raw_key)
    return MappingProxyType(frozen)



def _mapping_detection_sort_key(value: Mapping[object, object]) -> str:
    items = _safe_mapping_items(value)
    if items is None:
        return "mapping:" + no_hook_type_name(value) + ":unreadable"
    parts = (
        _detection_value_sort_key(key) + ":" + _detection_value_sort_key(item)
        for key, item in _ordered_detection_mapping_items(items)
    )
    return "{" + ",".join(parts) + "}"


def _sequence_detection_sort_key(value: object) -> str:
    items = _builtin_sequence_items(value)
    if items is None:
        return "sequence:" + no_hook_type_name(value) + ":unreadable"
    opener, closer = ("[", "]") if isinstance(value, (tuple, list)) else ("{", "}")
    return opener + ",".join(_detection_value_sort_key(item) for item in items) + closer


def _detection_value_sort_key(value: object) -> str:
    """Return a deterministic sort key without invoking caller-owned hooks."""
    if value is None or type(value) in (str, int, bool):
        sort_key = no_hook_json_sort_key(value)
    elif type(value) is float:
        metric, reason = no_hook_finite_float(value, allow_exact_text=False)
        sort_key = "float:unavailable" if reason else no_hook_json_sort_key(metric)
    elif isinstance(value, Mapping):
        sort_key = _mapping_detection_sort_key(value)
    elif isinstance(value, (tuple, list, set, frozenset)):
        sort_key = _sequence_detection_sort_key(value)
    else:
        materialized = no_hook_materialize(value, reason_prefix="detection_sort_key")
        sort_key = no_hook_json_sort_key(materialized)
    return sort_key



def freeze_detection_value(value: object) -> object:
    """Return a recursively immutable, deterministically ordered detection-stage value."""
    if type(value) is float:
        numeric, reason = no_hook_finite_float(
            value,
            reason="detection_numeric_unavailable",
            non_finite_reason="nonfinite_detection_float",
            allow_exact_text=False,
        )
        frozen = numeric if not reason else detection_unavailable_value(reason, value)
    elif isinstance(value, _JSON_PRIMITIVES):
        frozen = value
    elif isinstance(value, Mapping):
        frozen = _freeze_detection_mapping(value)
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = _builtin_sequence_items(value)
        if items is None:
            frozen = detection_unavailable_value("detection_iterable_unavailable", value)
        elif isinstance(value, (set, frozenset)):
            frozen = tuple(sorted((freeze_detection_value(item) for item in items), key=_detection_value_sort_key))
        else:
            frozen = tuple(freeze_detection_value(item) for item in items)
    else:
        frozen = detection_unavailable_value("detection_scalar_unavailable", value)
    return frozen


def thaw_detection_value(value: object) -> object:
    """Return a mutable JSON/reporting-safe copy of a frozen stage value."""
    if isinstance(value, Mapping):
        items = _safe_mapping_items(value)
        if items is None:
            return dict(no_hook_materialize(value, reason_prefix="detection_thaw_mapping"))
        return {key: thaw_detection_value(val) for key, val in items}
    if type(value) in (tuple, list):
        return [thaw_detection_value(item) for item in value]
    if type(value) is frozenset:
        return [thaw_detection_value(item) for item in sorted(value, key=_detection_value_sort_key)]
    return value


def frozen_tuple(value: object) -> tuple[object, ...]:
    """Normalize owned iterable stage values to immutable tuples."""
    if value is None:
        return ()
    items = _builtin_sequence_items(value)
    if items is not None:
        if isinstance(value, (set, frozenset)):
            return tuple(sorted((freeze_detection_value(item) for item in items), key=_detection_value_sort_key))
        return tuple(freeze_detection_value(item) for item in items)
    backed = _plain_backing_sequence_items(value)
    if backed is not None:
        return tuple(freeze_detection_value(item) for item in backed)
    return (detection_unavailable_value("detection_iterable_unavailable", value),)


def frozen_failure_records(failures: object) -> tuple[object, ...]:
    """Normalize failure evidence to immutable JSON/replay-ready records."""
    records: tuple[object, ...]
    try:
        records = failure_state_records(failures)
    except _DETECTION_RECOVERABLE_EXCEPTIONS:
        records = (detection_unavailable_value("detection_failure_records_unavailable", failures),)
    return frozen_tuple(records)


__all__ = (
    "detection_unavailable_value",
    "detection_value_or_default",
    "freeze_detection_value",
    "freeze_mapping_or_empty",
    "frozen_failure_records",
    "frozen_tuple",
    "frozen_tuple_or_empty",
    "safe_detection_bool",
    "safe_detection_text",
    "thaw_detection_value",
)
