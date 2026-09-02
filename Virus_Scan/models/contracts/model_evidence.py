"""Immutable generic evidence records for model-layer handoffs."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

import math

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
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
    return isinstance(value, float) and not math.isfinite(value)


def _safe_mapping_items(value: Mapping[object, object]) -> tuple[tuple[tuple[object, object], ...], str]:
    items = no_hook_mapping_items(value)
    if items is None:
        return (), "unreadable_model_evidence_mapping"
    try:
        return tuple(sorted(items, key=lambda item: model_contract_safe_text(item[0]))), ""
    except _RECOVERABLE_CONTRACT_EXCEPTIONS:
        return (), "unreadable_model_evidence_mapping"


def _safe_mapping_keys(value: Mapping[object, object]) -> tuple[tuple[object, ...], str]:
    items, reason = _safe_mapping_items(value)
    if reason:
        return (), reason
    return tuple(key for key, _item in items), ""


def _nonfinite_evidence_unavailable_record() -> Mapping[str, object]:
    return model_contract_unavailable_record("non_finite_model_evidence")


def _unsupported_model_evidence_value(value: object) -> Mapping[str, object]:
    return model_contract_unavailable_record("unsupported_model_evidence_value", value)


def _freeze_evidence_value(value: object) -> object:
    """Recursively detach caller-owned containers from model evidence output."""
    if _is_nonfinite_float(value):
        return _nonfinite_evidence_unavailable_record()
    if isinstance(value, Mapping):
        items, reason = _safe_mapping_items(value)
        if reason:
            return model_contract_unavailable_record(reason, value)
        frozen: dict[str, object] = {}
        for key, item in items:
            name = model_contract_safe_text(key)
            if _is_nonfinite_float(item):
                frozen[name] = None
                frozen[model_contract_unavailable_reason_key(name)] = "non_finite_model_evidence"
                continue
            frozen[name] = _freeze_evidence_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, (set, frozenset)):
        return tuple(_freeze_evidence_value(item) for item in sorted(value, key=model_contract_safe_text))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_evidence_value(item) for item in value)
    if isinstance(value, str):
        return model_contract_safe_text(value)
    if model_contract_json_safe_scalar(value):
        return value
    return _unsupported_model_evidence_value(value)


def make_model_evidence_record(
    values: Mapping[str, object],
    *,
    model_name: str,
    evidence_type: str,
    model_version: str,
) -> Mapping[str, object]:
    """Return an immutable deterministic model evidence mapping."""
    record: dict[str, object] = {}
    if not isinstance(values, Mapping):
        record["values_unavailable_reason"] = "non_mapping_model_evidence_values"
    else:
        items, reason = _safe_mapping_items(values)
        if reason:
            record["values_unavailable_reason"] = reason
            record["values_type"] = no_hook_type_name(values)
        else:
            for key, item in items:
                name = model_contract_safe_text(key)
                if _is_nonfinite_float(item):
                    record[name] = None
                    record[model_contract_unavailable_reason_key(name)] = "non_finite_model_evidence"
                    continue
                record[name] = _freeze_evidence_value(item)
    model_name_value, model_name_error = model_contract_text_field(
        model_name,
        field_name="model_name",
        default="unknown_model",
    )
    evidence_type_value, evidence_type_error = model_contract_text_field(
        evidence_type,
        field_name="evidence_type",
        default="unknown_evidence",
    )
    model_version_value, model_version_error = model_contract_text_field(
        model_version,
        field_name="model_version",
        default="model_evidence_record_v1",
    )
    record["model_name"] = model_name_value
    record["evidence_type"] = evidence_type_value
    record["model_version"] = model_version_value
    if model_name_error:
        record["model_name_unavailable_reason"] = model_name_error
    if evidence_type_error:
        record["evidence_type_unavailable_reason"] = evidence_type_error
    if model_version_error:
        record["model_version_unavailable_reason"] = model_version_error
    return MappingProxyType(record)


def materialize_model_evidence_record(record: Mapping[str, object]) -> dict[str, object]:
    """Materialize model evidence into deterministic JSON-safe primitives."""

    def materialize(value: object) -> object:
        if _is_nonfinite_float(value):
            return {
                "value": None,
                "unavailable_reason": "non_finite_model_evidence",
            }
        if isinstance(value, Mapping):
            items, reason = _safe_mapping_items(value)
            if reason:
                return {"value": None, "unavailable_reason": reason, "value_type": no_hook_type_name(value)}
            materialized: dict[str, object] = {}
            for key, item in items:
                name = model_contract_safe_text(key)
                if _is_nonfinite_float(item):
                    materialized[name] = None
                    materialized[model_contract_unavailable_reason_key(name)] = "non_finite_model_evidence"
                    continue
                materialized[name] = materialize(item)
            return materialized
        if isinstance(value, (set, frozenset)):
            return tuple(materialize(item) for item in sorted(value, key=model_contract_safe_text))
        if isinstance(value, (list, tuple)):
            return tuple(materialize(item) for item in value)
        if isinstance(value, str):
            return model_contract_safe_text(value)
        if model_contract_json_safe_scalar(value):
            return value
        return {
            "value": None,
            "unavailable_reason": "unsupported_model_evidence_value",
            "value_type": no_hook_type_name(value),
        }

    if not isinstance(record, Mapping):
        return {"unavailable_reason": "non_mapping_model_evidence_record", "value_type": no_hook_type_name(record)}
    items, reason = _safe_mapping_items(record)
    if reason:
        return {"unavailable_reason": reason, "value_type": no_hook_type_name(record)}
    out: dict[str, object] = {}
    for key, item in items:
        name = model_contract_safe_text(key)
        out[name] = materialize(item)
    return out



def make_temporal_overlay_record(
    values: Mapping[str, object],
    *,
    model_version: str = "temporal_overlay_record_v5",
) -> Mapping[str, object]:
    """Return immutable temporal overlay evidence with canonical metadata."""
    return make_model_evidence_record(
        values,
        model_name="temporal",
        evidence_type="temporal_overlay",
        model_version=model_version,
    )


def make_profile_evidence_record(
    values: Mapping[str, object],
    *,
    model_version: str = "profile_evidence_record_v1",
) -> Mapping[str, object]:
    """Return immutable profile evidence with canonical metadata."""
    return make_model_evidence_record(
        values,
        model_name="profiles",
        evidence_type="profile_evidence",
        model_version=model_version,
    )


def make_cluster_evidence_record(
    values: Mapping[str, object],
    *,
    model_version: str = "cluster_evidence_record_v1",
) -> Mapping[str, object]:
    """Return immutable clustering evidence with canonical metadata."""
    return make_model_evidence_record(
        values,
        model_name="clustering",
        evidence_type="cluster_evidence",
        model_version=model_version,
    )


def make_graph_evidence_record(
    values: Mapping[str, object],
    *,
    model_version: str = "graph_evidence_record_v1",
) -> Mapping[str, object]:
    """Return immutable graph evidence with canonical metadata."""
    return make_model_evidence_record(
        values,
        model_name="graph",
        evidence_type="graph_evidence",
        model_version=model_version,
    )


__all__ = (
    "make_cluster_evidence_record",
    "make_graph_evidence_record",
    "make_model_evidence_record",
    "make_profile_evidence_record",
    "make_temporal_overlay_record",
    "materialize_model_evidence_record",
)
