"""Immutable feature-bundle records for model evidence handoffs."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

import math

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items_status,
    no_hook_type_name,
)
from Virus_Scan.models.contracts.text_boundaries import (
    model_contract_json_safe_scalar,
    model_contract_safe_text,
    model_contract_text_field,
    model_contract_unavailable_record,
    model_contract_unavailable_reason_key,
)

_RECOVERABLE_CONTRACT_EXCEPTIONS = (
    ArithmeticError,
    AttributeError,
    KeyError,
    LookupError,
    OSError,
    RuntimeError,
    TypeError,
    UnicodeError,
    ValueError,
)


def _is_nonfinite_float(value: object) -> bool:
    return type(value) is float and not math.isfinite(value)


def _owned_mapping_items_status(value: object) -> tuple[tuple[tuple[object, object], ...] | None, str]:
    items, reason = no_hook_mapping_items_status(value)
    if items is None:
        return None, reason or "unreadable_model_feature_mapping"
    try:
        return tuple(sorted(items, key=lambda item: model_contract_safe_text(item[0]))), ""
    except _RECOVERABLE_CONTRACT_EXCEPTIONS:
        return None, "unreadable_model_feature_mapping"


def _owned_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    items, _reason = _owned_mapping_items_status(value)
    return items


def _nonfinite_feature_unavailable_record() -> Mapping[str, object]:
    return model_contract_unavailable_record("non_finite_model_feature")


def _unsupported_model_feature_value(value: object) -> Mapping[str, object]:
    return model_contract_unavailable_record("unsupported_model_feature_value", value)


def _freeze_model_value(value: object) -> object:
    """Recursively detach caller-owned containers for model feature output."""
    if _is_nonfinite_float(value):
        return _nonfinite_feature_unavailable_record()
    items = _owned_mapping_items(value)
    if items is not None:
        frozen: dict[str, object] = {}
        for key, item in items:
            name = model_contract_safe_text(key)
            if _is_nonfinite_float(item):
                frozen[name] = None
                frozen[model_contract_unavailable_reason_key(name)] = "non_finite_model_feature"
                continue
            frozen[name] = _freeze_model_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, Mapping):
        return model_contract_unavailable_record("unreadable_model_feature_mapping", value)
    if type(value) in (set, frozenset):
        return tuple(_freeze_model_value(item) for item in sorted(value, key=model_contract_safe_text))
    if type(value) in (list, tuple):
        return tuple(_freeze_model_value(item) for item in value)
    if isinstance(value, str):
        return model_contract_safe_text(value)
    if model_contract_json_safe_scalar(value):
        return value
    return _unsupported_model_feature_value(value)


def make_model_feature_bundle(values: Mapping[str, object], *, model_version: str) -> Mapping[str, object]:
    """Return an immutable, deterministic feature bundle mapping."""
    frozen: dict[str, object] = {}
    items = _owned_mapping_items(values)
    if items is None:
        frozen["values_unavailable_reason"] = "non_mapping_model_feature_bundle" if not isinstance(values, Mapping) else "unreadable_model_feature_mapping"
        frozen["values_type"] = no_hook_type_name(values)
    else:
        for key, item in items:
            name = model_contract_safe_text(key)
            if _is_nonfinite_float(item):
                frozen[name] = None
                frozen[model_contract_unavailable_reason_key(name)] = "non_finite_model_feature"
                continue
            frozen[name] = _freeze_model_value(item)
    model_version_value, model_version_error = model_contract_text_field(
        model_version,
        field_name="model_version",
        default="model_feature_bundle_v1",
    )
    frozen["model_version"] = model_version_value
    if model_version_error:
        frozen["model_version_unavailable_reason"] = model_version_error
    return MappingProxyType(frozen)


def materialize_model_feature_bundle(bundle: Mapping[str, object]) -> dict[str, object]:
    """Materialize a model feature bundle into deterministic JSON-safe primitives."""

    def materialize(value: object) -> object:
        if _is_nonfinite_float(value):
            return {
                "value": None,
                "unavailable_reason": "non_finite_model_feature",
            }
        items = _owned_mapping_items(value)
        if items is not None:
            materialized: dict[str, object] = {}
            for key, item in items:
                name = model_contract_safe_text(key)
                if _is_nonfinite_float(item):
                    materialized[name] = None
                    materialized[model_contract_unavailable_reason_key(name)] = "non_finite_model_feature"
                    continue
                materialized[name] = materialize(item)
            return materialized
        if isinstance(value, Mapping):
            return {"value": None, "unavailable_reason": "unreadable_model_feature_mapping", "value_type": no_hook_type_name(value)}
        if type(value) in (set, frozenset):
            return tuple(materialize(item) for item in sorted(value, key=model_contract_safe_text))
        if type(value) in (list, tuple):
            return tuple(materialize(item) for item in value)
        if isinstance(value, str):
            return model_contract_safe_text(value)
        if model_contract_json_safe_scalar(value):
            return value
        return {
            "value": None,
            "unavailable_reason": "unsupported_model_feature_value",
            "value_type": no_hook_type_name(value),
        }

    items = _owned_mapping_items(bundle)
    if items is None:
        reason = "non_mapping_model_feature_bundle" if not isinstance(bundle, Mapping) else "unreadable_model_feature_mapping"
        return {"unavailable_reason": reason, "value_type": no_hook_type_name(bundle)}
    out: dict[str, object] = {}
    for key, item in items:
        name = model_contract_safe_text(key)
        out[name] = materialize(item)
    return out


__all__ = ("make_model_feature_bundle", "materialize_model_feature_bundle")
