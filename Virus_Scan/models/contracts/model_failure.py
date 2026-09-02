"""Immutable model failure and cold-start records for model-layer handoffs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

import math

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_type_name,
)
from Virus_Scan.models.contracts.text_boundaries import (
    model_contract_field_reason,
    model_contract_json_safe_scalar,
    model_contract_metric_reason,
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


def _affected_fields_tuple(value: Iterable[object] | None) -> tuple[tuple[str, ...], str]:
    items, reason = _safe_iterable(value)
    if reason:
        return (), reason
    return tuple(model_contract_safe_text(field) for field in sorted(items, key=model_contract_safe_text)), ""


def _safe_iterable(value: object) -> tuple[tuple[object, ...], str]:
    if value is None:
        return (), ""
    if type(value) is tuple:
        return tuple(value), ""
    if type(value) is list:
        return tuple(list.__iter__(value)), ""
    if type(value) is frozenset:
        return tuple(frozenset.__iter__(value)), ""
    if type(value) is set:
        return tuple(set.__iter__(value)), ""
    return (), "unreadable_model_failure_iterable"


def _safe_mapping_items(value: Mapping[object, object]) -> tuple[tuple[tuple[object, object], ...], str]:
    items = no_hook_mapping_items(value)
    if items is None:
        plain_data = no_hook_plain_instance_dict(value)
        backing = dict.get(plain_data, "_data") if plain_data is not None else None
        if type(backing) is dict:
            try:
                items = tuple(dict.items(backing))
            except _RECOVERABLE_CONTRACT_EXCEPTIONS:
                items = None
    if items is None:
        return (), "unreadable_model_failure_mapping"
    try:
        return tuple(sorted(items, key=lambda item: model_contract_safe_text(item[0]))), ""
    except _RECOVERABLE_CONTRACT_EXCEPTIONS:
        return (), "unreadable_model_failure_mapping"


def _safe_mapping_keys(value: Mapping[object, object]) -> tuple[tuple[object, ...], str]:
    items, reason = _safe_mapping_items(value)
    if reason:
        return (), reason
    return tuple(key for key, _item in items), ""

def _safe_mapping_get(value: Mapping[object, object], key: object) -> tuple[bool, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        return False, None
    for item_key, item_value in items:
        if item_key is key:
            return True, item_value
    return False, None

def _nonfinite_failure_detail_unavailable_record() -> Mapping[str, object]:
    return model_contract_unavailable_record("non_finite_model_failure_detail")


def _freeze_failure_value(value: object) -> object:
    """Recursively detach caller-owned containers from failure evidence."""
    if _is_nonfinite_float(value):
        return _nonfinite_failure_detail_unavailable_record()
    if isinstance(value, Mapping):
        items, reason = _safe_mapping_items(value)
        if reason:
            return model_contract_unavailable_record(reason, value)
        frozen: dict[str, object] = {}
        for key, item in items:
            name = model_contract_safe_text(key)
            if _is_nonfinite_float(item):
                frozen[name] = None
                frozen[model_contract_unavailable_reason_key(name)] = "non_finite_model_failure_detail"
                continue
            frozen[name] = _freeze_failure_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, (set, frozenset)):
        return tuple(_freeze_failure_value(item) for item in sorted(value, key=model_contract_safe_text))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_failure_value(item) for item in value)
    if isinstance(value, str):
        return model_contract_safe_text(value)
    if model_contract_json_safe_scalar(value):
        return value
    return model_contract_unavailable_record("unsupported_model_failure_detail_value", value)


def _materialize_failure_value(value: object) -> object:
    if _is_nonfinite_float(value):
        return {
            "value": None,
            "unavailable_reason": "non_finite_model_failure_detail",
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
                materialized[model_contract_unavailable_reason_key(name)] = "non_finite_model_failure_detail"
                continue
            materialized[name] = _materialize_failure_value(item)
        return materialized
    if isinstance(value, (set, frozenset)):
        return tuple(_materialize_failure_value(item) for item in sorted(value, key=model_contract_safe_text))
    if isinstance(value, (list, tuple)):
        return tuple(_materialize_failure_value(item) for item in value)
    if isinstance(value, str):
        return model_contract_safe_text(value)
    if model_contract_json_safe_scalar(value):
        return value
    return {"value": None, "unavailable_reason": "unsupported_model_failure_detail_value", "value_type": no_hook_type_name(value)}


def _nonnegative_support_metric(value: object, *, field_name: str) -> tuple[int, str]:
    if value is None:
        return 0, ""
    if isinstance(value, str) and str.strip(str.__str__(value)) == "":
        return 0, ""
    if type(value) is bool:
        return 0, model_contract_metric_reason("non_numeric", field_name)
    if type(value) is int:
        metric = float(value)
    elif type(value) is float:
        metric = value
    elif isinstance(value, str):
        try:
            metric = float(str.__str__(value).strip())
        except _RECOVERABLE_CONTRACT_EXCEPTIONS:
            return 0, model_contract_metric_reason("non_numeric", field_name)
    elif type(value) in (bytes, bytearray):
        try:
            metric = float(bytes(value).decode("utf-8", "replace").strip())
        except _RECOVERABLE_CONTRACT_EXCEPTIONS:
            return 0, model_contract_metric_reason("non_numeric", field_name)
    else:
        return 0, model_contract_metric_reason("non_numeric", field_name)
    if not math.isfinite(metric):
        return 0, model_contract_metric_reason("non_finite", field_name)
    if metric < 0.0:
        return 0, model_contract_metric_reason("negative", field_name)
    if not metric.is_integer():
        return 0, model_contract_metric_reason("non_integer", field_name)
    return int(metric), ""


def _boolean_flag(value: object, *, field_name: str, default: bool) -> tuple[bool, str]:
    if type(value) is bool:
        return value, ""
    if value is None:
        return default, ""
    return default, model_contract_field_reason("non_boolean", field_name)


def make_model_failure_record(
    *,
    model_name: object,
    failure_type: object,
    reason: object,
    affected_fields: Iterable[object] | None = None,
    degraded: object = True,
    output_affecting: object = True,
    details: Mapping[str, object] | None = None,
    model_version: str = "model_failure_record_v1",
) -> Mapping[str, object]:
    """Return immutable deterministic evidence for a model computation failure."""
    model_name_value, model_name_error = model_contract_text_field(
        model_name,
        field_name="model_name",
        default="unknown_model",
    )
    failure_type_value, failure_type_error = model_contract_text_field(
        failure_type,
        field_name="failure_type",
        default="unknown_failure",
    )
    reason_value, reason_error = model_contract_text_field(
        reason,
        field_name="reason",
        default="model_failure",
    )
    model_version_value, model_version_error = model_contract_text_field(
        model_version,
        field_name="model_version",
        default="model_failure_record_v1",
    )
    affected_fields_value, affected_fields_error = _affected_fields_tuple(affected_fields)
    degraded_value, degraded_error = _boolean_flag(degraded, field_name="degraded", default=True)
    output_affecting_value, output_affecting_error = _boolean_flag(
        output_affecting,
        field_name="output_affecting",
        default=True,
    )
    record = {
        "model_name": model_name_value,
        "failure_type": failure_type_value,
        "reason": reason_value,
        "affected_fields": affected_fields_value,
        "degraded": degraded_value,
        "output_affecting": output_affecting_value,
        "details": _freeze_failure_value(details if details is not None else {}),
        "model_version": model_version_value,
    }
    for field_name, field_error in (
        ("model_name", model_name_error),
        ("failure_type", failure_type_error),
        ("reason", reason_error),
        ("model_version", model_version_error),
        ("affected_fields", affected_fields_error),
        ("degraded", degraded_error),
        ("output_affecting", output_affecting_error),
    ):
        if field_error:
            record[model_contract_unavailable_reason_key(field_name)] = field_error
    return MappingProxyType(record)


def make_cold_start_record(
    *,
    model_name: object,
    reason: object,
    required_support: object = 0,
    observed_support: object = 0,
    affected_fields: Iterable[object] | None = None,
    model_version: str = "cold_start_record_v1",
) -> Mapping[str, object]:
    """Return immutable deterministic evidence for explicit model cold start."""
    required_support_value, required_support_error = _nonnegative_support_metric(
        required_support,
        field_name="required_support",
    )
    observed_support_value, observed_support_error = _nonnegative_support_metric(
        observed_support,
        field_name="observed_support",
    )
    model_name_value, model_name_error = model_contract_text_field(
        model_name,
        field_name="model_name",
        default="unknown_model",
    )
    reason_value, reason_error = model_contract_text_field(
        reason,
        field_name="reason",
        default="cold_start",
    )
    model_version_value, model_version_error = model_contract_text_field(
        model_version,
        field_name="model_version",
        default="cold_start_record_v1",
    )
    affected_fields_value, affected_fields_error = _affected_fields_tuple(affected_fields)
    record = {
        "model_name": model_name_value,
        "failure_type": "cold_start",
        "reason": reason_value,
        "required_support": required_support_value,
        "observed_support": observed_support_value,
        "affected_fields": affected_fields_value,
        "degraded": True,
        "output_affecting": True,
        "model_version": model_version_value,
    }
    if model_name_error:
        record["model_name_unavailable_reason"] = model_name_error
    if reason_error:
        record["reason_unavailable_reason"] = reason_error
    if model_version_error:
        record["model_version_unavailable_reason"] = model_version_error
    if affected_fields_error:
        record["affected_fields_unavailable_reason"] = affected_fields_error
    if required_support_error:
        record["required_support_unavailable_reason"] = required_support_error
    if observed_support_error:
        record["observed_support_unavailable_reason"] = observed_support_error
    return MappingProxyType(record)


def materialize_model_failure_record(record: Mapping[str, object]) -> dict[str, object]:
    """Materialize a model failure/cold-start record deterministically."""
    if not isinstance(record, Mapping):
        return {"unavailable_reason": "non_mapping_model_failure_record", "value_type": no_hook_type_name(record)}
    items, reason = _safe_mapping_items(record)
    if reason:
        return {"unavailable_reason": reason, "value_type": no_hook_type_name(record)}
    out: dict[str, object] = {}
    for key, item in items:
        name = model_contract_safe_text(key)
        out[name] = _materialize_failure_value(item)
    return out


__all__ = (
    "make_cold_start_record",
    "make_model_failure_record",
    "materialize_model_failure_record",
)
