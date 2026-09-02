"""Public adaptive-scoring input coercion helpers.

Adaptive scoring is the detection-owned consumer of model evidence.  Public
callers may hand it hostile or mutable containers, so boundary code must freeze
inputs without asking for caller-owned truthiness. Malformed public mapping
inputs emit explicit rejection evidence instead of being normalized to empty
mappings.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import NoReturn

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_duplicate_key,
    no_hook_json_key,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_type_name,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS


_UNSUPPORTED_ADAPTIVE_PUBLIC_TEXT_VALUE = "unsupported adaptive public text value"


def _raise_unsupported_adaptive_public_text_value() -> NoReturn:
    raise TypeError(_UNSUPPORTED_ADAPTIVE_PUBLIC_TEXT_VALUE)


def _exact_public_scalar(value: object) -> object:
    if type(value) is str:
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) is bytes:
        return value
    return value


def _exact_public_tuple(value: object) -> tuple[object, ...]:
    if type(value) is tuple:
        return value
    if type(value) is list:
        return tuple(value)
    return ()


def adaptive_public_sequence(value: object) -> tuple[object, ...]:
    """Freeze public sequence input without caller-owned iteration/truthiness.

    Only repository-owned primitive scalars and exact builtin sequence containers
    are consumed. Unknown iterables are rejected instead of invoking
    ``__iter__``/``__len__`` on caller-owned objects.
    """
    if value is None:
        return ()
    if isinstance(value, str) or type(value) is bytes:
        return (_exact_public_scalar(value),)
    return _exact_public_tuple(value)


def adaptive_public_event_sequence(value: object) -> tuple[object, ...]:
    """Freeze ordered behavior events without caller-owned iteration.

    Exact dict/mapping-proxy observations are preserved as single observations
    so their keys are not mistaken for behavior events. Unknown mapping-like or
    iterable values are rejected without touching mapping/iteration hooks.
    """
    if value is None:
        return ()
    if isinstance(value, str) or type(value) is bytes:
        return (_exact_public_scalar(value),)
    if type(value) is dict or isinstance(value, MappingProxyType):
        return (value,)
    return _exact_public_tuple(value)


def _adaptive_public_exact_text(value: object) -> str:
    if type(value) is str:
        return value
    if isinstance(value, str):
        return str.__str__(value)
    _raise_unsupported_adaptive_public_text_value()


def adaptive_public_text_with_reason(value: object, *, default: str = "") -> tuple[str, str | None]:
    """Return stable text plus an explicit coercion-failure reason."""
    if value is None:
        return default, None
    try:
        text = _adaptive_public_exact_text(value).strip()
    except RECOVERABLE_RUNTIME_ERRORS:
        return default, "text_coercion_failed"
    return (text or default), None


def adaptive_public_text(value: object, *, default: str = "") -> str:
    """Return stable public text without probing truthiness."""
    return adaptive_public_text_with_reason(value, default=default)[0]


def _adaptive_input_failure(value: object, reason: str) -> dict[str, object]:
    return {
        "adaptive_input_state": "rejected",
        "adaptive_input_rejected": True,
        "adaptive_input_valid": False,
        "adaptive_input_reason": reason,
        "unavailable_reason": reason,
        "failure_reason": reason,
        "error_category": "adaptive_public_input_rejected",
        "error_source": "detection.scoring.adaptive.public_inputs",
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "replay_must_record": True,
    }


def _adaptive_public_mapping_from_items(value: object, reason: str) -> dict[str, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        return _adaptive_input_failure(value, reason)
    out: dict[str, object] = {}
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(
            key,
            index,
            prefix="adaptive_public_input_key",
        )
        if key_text in out:
            key_text = no_hook_duplicate_key(key_text, index)
        if key_reason:
            out[key_text] = _adaptive_input_failure(key, key_reason)
            continue
        out[key_text] = no_hook_materialize(
            item,
            reason_prefix="adaptive_public_input",
        )
    return out


def adaptive_public_mapping_with_state(value: object) -> tuple[dict[str, object], str]:
    """Freeze a public mapping and return its explicit input state.

    ``None`` and an exact empty built-in dict are explicit neutral
    no-input/valid-empty cases. Unknown mapping-like values and mapping-proxy
    materialization failures emit adaptive-input evidence instead of normalizing
    to ``{}``.
    """
    if value is None:
        return {}, "adaptive_input_not_provided"
    if type(value) is dict or isinstance(value, (MappingProxyType, dict)):
        mapping = _adaptive_public_mapping_from_items(
            value,
            "adaptive_input_materialization_failed",
        )
    elif isinstance(value, Mapping):
        mapping = _adaptive_input_failure(value, "adaptive_input_mapping_rejected")
    else:
        mapping = _adaptive_input_failure(value, "adaptive_input_not_mapping")
    rejection_reason = adaptive_public_input_rejection_reason(mapping)
    if rejection_reason is not None:
        return mapping, rejection_reason
    if type(mapping) is dict and not mapping:
        return mapping, "adaptive_input_valid_empty"
    return mapping, "adaptive_input_available"


def adaptive_public_mapping(value: object) -> dict[str, object]:
    """Freeze readable mappings without caller-owned mapping hooks."""
    return adaptive_public_mapping_with_state(value)[0]


def adaptive_public_input_rejection_reason(value: Mapping[str, object]) -> str | None:
    """Return the reason from a canonical adaptive-input rejection record."""
    if type(value) is not dict:
        return None
    if value.get("adaptive_input_rejected") is not True:
        return None
    reason = value.get("adaptive_input_reason")
    return reason if type(reason) is str and reason else "adaptive_public_input_rejected"


def adaptive_public_node_reference(node: object) -> tuple[object | None, str | None]:
    if isinstance(node, (dict, MappingProxyType, Mapping)):
        mapping = adaptive_public_mapping(node)
        if mapping:
            if mapping.get("adaptive_input_rejected") is True:
                reason = mapping.get("adaptive_input_reason")
                return None, reason if type(reason) is str else "adaptive_probability_node_rejected"
            node_value = mapping.get('path')
            if node_value is None:
                node_value = mapping.get('node')
            node_key, reason = adaptive_public_text_with_reason(node_value)
            node_for_model = node_key or None
        else:
            node_key, reason = "", None
            node_for_model = None
    else:
        node_key, reason = adaptive_public_text_with_reason(node)
        node_for_model = node_key or None
    if node is not None and reason:
        return None, 'adaptive_probability_node_coercion_failed'
    return node_for_model, None


def _adaptive_input_field_missing(key: object, reason: str) -> dict[str, object]:
    evidence: dict[str, object] = {
        "adaptive_input_state": reason,
        "adaptive_input_field_unavailable": True,
        "adaptive_input_valid": False,
        "adaptive_input_reason": reason,
        "final_json_must_record": True,
        "replay_must_record": True,
    }
    if isinstance(key, str):
        evidence["adaptive_input_field"] = str.__str__(key)
    return evidence


def _adaptive_input_field_failure(value: object, key: object, reason: str) -> dict[str, object]:
    evidence = _adaptive_input_failure(value, reason)
    evidence["adaptive_input_field_unavailable"] = True
    if isinstance(key, str):
        evidence["adaptive_input_field"] = str.__str__(key)
    return evidence


def adaptive_public_mapping_field(value: object, key: object) -> dict[str, object]:
    """Read a nested mapping field without truth-testing either mapping.

    Missing, absent, rejected, and non-materializable nested fields remain
    explicit evidence instead of collapsing into ``{}``.
    """
    mapping, state = adaptive_public_mapping_with_state(value)
    rejection_reason = adaptive_public_input_rejection_reason(mapping)
    if rejection_reason is not None:
        return mapping
    if type(key) is not str:
        return _adaptive_input_field_failure(key, key, "adaptive_input_field_key_rejected")
    if not mapping:
        reason = "adaptive_input_not_provided" if state == "adaptive_input_not_provided" else "adaptive_input_field_missing"
        return _adaptive_input_field_missing(key, reason)
    child = mapping.get(key)
    if child is None:
        return _adaptive_input_field_missing(key, "adaptive_input_field_missing")
    return adaptive_public_mapping(child)


__all__ = (
    "adaptive_public_event_sequence",
    "adaptive_public_input_rejection_reason",
    "adaptive_public_mapping",
    "adaptive_public_mapping_field",
    "adaptive_public_mapping_with_state",
    "adaptive_public_node_reference",
    "adaptive_public_sequence",
    "adaptive_public_text",
    "adaptive_public_text_with_reason",
)
