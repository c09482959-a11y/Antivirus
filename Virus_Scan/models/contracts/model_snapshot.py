"""Immutable snapshot and replay-comparison records for model-layer handoffs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

import math

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.models.contracts.text_boundaries import (
    model_contract_field_reason,
    model_contract_json_safe_scalar,
    model_contract_safe_text,
    model_contract_text_field,
    model_contract_unavailable_reason_key,
)

@dataclass(frozen=True, slots=True)
class ModelSnapshotErrors:
    model_name: str
    snapshot_type: str
    model_version: str
    ready: str
    degraded: str
    reason: str
    values_read: str
    failures_iter: str
    contract_errors: tuple[str, ...]


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


def _safe_iterable(value: object, *, reason: str) -> tuple[tuple[object, ...], str]:
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
    return (), reason


def _safe_mapping_items(value: Mapping[object, object]) -> tuple[tuple[tuple[object, object], ...], str]:
    items = no_hook_mapping_items(value)
    if items is None:
        return (), "unreadable_model_snapshot_mapping"
    try:
        return tuple(sorted(items, key=lambda item: model_contract_safe_text(item[0]))), ""
    except _RECOVERABLE_CONTRACT_EXCEPTIONS:
        return (), "unreadable_model_snapshot_mapping"


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

def _freeze_contract_value(value: object, *, reason: str) -> object:
    if _is_nonfinite_float(value):
        return MappingProxyType({"value": None, "unavailable_reason": reason})
    if isinstance(value, Mapping):
        items, read_reason = _safe_mapping_items(value)
        if read_reason:
            return MappingProxyType({"value": None, "unavailable_reason": read_reason, "value_type": no_hook_type_name(value)})
        frozen: dict[str, object] = {}
        for key, item in items:
            name = model_contract_safe_text(key)
            if _is_nonfinite_float(item):
                frozen[name] = None
                frozen[model_contract_unavailable_reason_key(name)] = reason
                continue
            frozen[name] = _freeze_contract_value(item, reason=reason)
        return MappingProxyType(frozen)
    if isinstance(value, (set, frozenset)):
        return tuple(_freeze_contract_value(item, reason=reason) for item in sorted(value, key=model_contract_safe_text))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_contract_value(item, reason=reason) for item in value)
    if isinstance(value, str):
        return model_contract_safe_text(value)
    if model_contract_json_safe_scalar(value):
        return value
    return MappingProxyType({"value": None, "unavailable_reason": "unsupported_model_snapshot_value", "value_type": no_hook_type_name(value)})


def _materialize_contract_value(value: object, *, reason: str) -> object:
    if _is_nonfinite_float(value):
        return {"value": None, "unavailable_reason": reason}
    if isinstance(value, Mapping):
        items, read_reason = _safe_mapping_items(value)
        if read_reason:
            return {"value": None, "unavailable_reason": read_reason, "value_type": no_hook_type_name(value)}
        materialized: dict[str, object] = {}
        for key, item in items:
            name = model_contract_safe_text(key)
            if _is_nonfinite_float(item):
                materialized[name] = None
                materialized[model_contract_unavailable_reason_key(name)] = reason
                continue
            materialized[name] = _materialize_contract_value(item, reason=reason)
        return materialized
    if isinstance(value, (set, frozenset)):
        return tuple(_materialize_contract_value(item, reason=reason) for item in sorted(value, key=model_contract_safe_text))
    if isinstance(value, (list, tuple)):
        return tuple(_materialize_contract_value(item, reason=reason) for item in value)
    if isinstance(value, str):
        return model_contract_safe_text(value)
    if model_contract_json_safe_scalar(value):
        return value
    return {"value": None, "unavailable_reason": "unsupported_model_snapshot_value", "value_type": no_hook_type_name(value)}



def _text_present_status(value: object) -> tuple[bool, str]:
    if value is None:
        return False, ""
    try:
        return str.strip(model_contract_safe_text(value)) != "", ""
    except _RECOVERABLE_CONTRACT_EXCEPTIONS:
        return False, "unreadable_model_snapshot_reason"


def _text_present(value: object) -> bool:
    present, _reason = _text_present_status(value)
    return present

def _optional_reason(value: object) -> tuple[str | None, str]:
    if value is None:
        return None, ""
    if not isinstance(value, str):
        return None, "non_text_reason"
    reason = str.strip(model_contract_safe_text(value))
    if reason == "":
        return None, "blank_reason"
    return reason, ""


def _boolean_value(value: object, *, field_name: str, default: bool) -> tuple[bool, str]:
    if isinstance(value, bool):
        return value, ""
    if value is None:
        return default, ""
    return default, model_contract_field_reason("non_boolean", field_name)


def _failure_records(failures: Iterable[Mapping[str, object]] | None) -> tuple[Mapping[str, object], ...]:
    frozen: list[Mapping[str, object]] = []
    items, iterable_reason = _safe_iterable(failures, reason="unreadable_model_snapshot_failures")
    if iterable_reason:
        return (MappingProxyType({"unavailable_reason": iterable_reason}),)
    for failure in items:
        if isinstance(failure, Mapping):
            frozen.append(_freeze_contract_value(failure, reason="non_finite_model_snapshot_failure_detail"))
        else:
            frozen.append(MappingProxyType({"unavailable_reason": "non_mapping_model_snapshot_failure", "value_type": no_hook_type_name(failure)}))
    return tuple(frozen)



def _apply_model_snapshot_errors(record: dict[str, object], errors: ModelSnapshotErrors) -> None:
    if errors.values_read:
        record["values_unavailable_reason"] = errors.values_read
        record["ready"] = False
        record["degraded"] = True
        if not _text_present(record["reason"]):
            record["reason"] = errors.values_read
    if errors.failures_iter:
        record["failures_unavailable_reason"] = errors.failures_iter
        record["ready"] = False
        record["degraded"] = True
        if not _text_present(record["reason"]):
            record["reason"] = errors.failures_iter
    for field_name, error in (
        ("model_name", errors.model_name),
        ("snapshot_type", errors.snapshot_type),
        ("model_version", errors.model_version),
        ("ready", errors.ready),
        ("degraded", errors.degraded),
        ("reason", errors.reason),
    ):
        if error:
            record[model_contract_unavailable_reason_key(field_name)] = error
    if errors.contract_errors and not _text_present(record["reason"]):
        record["reason"] = errors.contract_errors[0]
    if record["degraded"] and not _text_present(record["reason"]):
        record["reason"] = "degraded_model_snapshot"
    if not record["ready"] and not _text_present(record["reason"]):
        record["reason"] = "model_snapshot_not_ready"

def make_model_snapshot(
    values: Mapping[str, object],
    *,
    model_name: object,
    snapshot_type: object,
    model_version: object,
    ready: object = True,
    degraded: object = False,
    reason: object = None,
    failures: Iterable[Mapping[str, object]] | None = None,
) -> Mapping[str, object]:
    """Return an immutable deterministic model snapshot record."""
    model_name_value, model_name_error = model_contract_text_field(
        model_name, field_name="model_name", default="unknown_model", invalid_prefix="non_text"
    )
    snapshot_type_value, snapshot_type_error = model_contract_text_field(
        snapshot_type, field_name="snapshot_type", default="unknown_snapshot", invalid_prefix="non_text"
    )
    model_version_value, model_version_error = model_contract_text_field(
        model_version, field_name="model_version", default="model_snapshot_v1", invalid_prefix="non_text"
    )
    ready_value, ready_error = _boolean_value(ready, field_name="ready", default=False)
    degraded_value, degraded_error = _boolean_value(degraded, field_name="degraded", default=True)
    reason_value, reason_error = _optional_reason(reason)
    if isinstance(values, Mapping):
        _value_keys, values_read_error = _safe_mapping_keys(values)
    else:
        values_read_error = "non_mapping_model_snapshot_values"
    _failure_items, failures_iter_error = _safe_iterable(
        failures, reason="unreadable_model_snapshot_failures"
    )
    contract_errors = tuple(
        error
        for error in (
            model_name_error, snapshot_type_error, model_version_error, ready_error,
            degraded_error, reason_error, values_read_error, failures_iter_error,
        )
        if error
    )
    record_ready = ready_value and not degraded_value and not contract_errors
    record: dict[str, object] = {
        "model_name": model_name_value,
        "snapshot_type": snapshot_type_value,
        "model_version": model_version_value,
        "ready": record_ready,
        "degraded": degraded_value or bool(contract_errors),
        "reason": reason_value,
        "values": _freeze_contract_value(values, reason="non_finite_model_snapshot_value")
        if isinstance(values, Mapping)
        else MappingProxyType({}),
        "failures": _failure_records(failures),
    }
    _apply_model_snapshot_errors(
        record,
        ModelSnapshotErrors(
            model_name=model_name_error,
            snapshot_type=snapshot_type_error,
            model_version=model_version_error,
            ready=ready_error,
            degraded=degraded_error,
            reason=reason_error,
            values_read=values_read_error,
            failures_iter=failures_iter_error,
            contract_errors=contract_errors,
        ),
    )
    return MappingProxyType(record)


def materialize_model_snapshot(snapshot: Mapping[str, object]) -> dict[str, object]:
    """Materialize a model snapshot into deterministic JSON-safe primitives."""
    if not isinstance(snapshot, Mapping):
        return {"unavailable_reason": "non_mapping_model_snapshot", "value_type": no_hook_type_name(snapshot)}
    items, reason = _safe_mapping_items(snapshot)
    if reason:
        return {"unavailable_reason": reason, "value_type": no_hook_type_name(snapshot)}
    out: dict[str, object] = {}
    for key, item in items:
        name = model_contract_safe_text(key)
        out[name] = _materialize_contract_value(item, reason="non_finite_model_snapshot_value")
    return out


def make_replay_model_comparison_record(
    *,
    model_name: object,
    expected: object,
    actual: object,
    matched: object,
    mismatch_fields: Iterable[object] | None = None,
    reason: object = None,
    model_version: object = "replay_model_comparison_v1",
) -> Mapping[str, object]:
    """Return immutable deterministic replay comparison evidence for model outputs."""
    model_name_value, model_name_error = model_contract_text_field(
        model_name,
        field_name="model_name",
        default="unknown_model",
        invalid_prefix="non_text",
    )
    model_version_value, model_version_error = model_contract_text_field(
        model_version,
        field_name="model_version",
        default="replay_model_comparison_v1",
        invalid_prefix="non_text",
    )
    matched_value, matched_error = _boolean_value(matched, field_name="matched", default=False)
    reason_value, reason_error = _optional_reason(reason)
    raw_fields, fields_error = _safe_iterable(mismatch_fields, reason="unreadable_replay_mismatch_fields")
    fields = tuple(model_contract_safe_text(field) for field in sorted(raw_fields, key=model_contract_safe_text))
    expected_read_error = ""
    actual_read_error = ""
    if isinstance(expected, Mapping):
        _expected_keys, expected_read_error = _safe_mapping_keys(expected)
    else:
        expected_read_error = "non_mapping_replay_expected"
    if isinstance(actual, Mapping):
        _actual_keys, actual_read_error = _safe_mapping_keys(actual)
    else:
        actual_read_error = "non_mapping_replay_actual"
    comparison_unavailable = bool(expected_read_error or actual_read_error or fields_error)
    record = {
        "model_name": model_name_value,
        "expected": _freeze_contract_value(expected, reason="non_finite_replay_expected_value")
        if isinstance(expected, Mapping)
        else MappingProxyType({}),
        "actual": _freeze_contract_value(actual, reason="non_finite_replay_actual_value")
        if isinstance(actual, Mapping)
        else MappingProxyType({}),
        "matched": matched_value and not matched_error and not fields and not comparison_unavailable,
        "mismatch_fields": fields,
        "reason": reason_value,
        "model_version": model_version_value,
    }
    if expected_read_error:
        record["expected_unavailable_reason"] = expected_read_error
    if actual_read_error:
        record["actual_unavailable_reason"] = actual_read_error
    if model_name_error:
        record["model_name_unavailable_reason"] = model_name_error
    if model_version_error:
        record["model_version_unavailable_reason"] = model_version_error
    if matched_error:
        record["matched_unavailable_reason"] = matched_error
    if fields_error:
        record["mismatch_fields_unavailable_reason"] = fields_error
    if reason_error:
        record["reason_unavailable_reason"] = reason_error
    if not record["matched"] and not record["reason"]:
        record["reason"] = "replay_model_evidence_mismatch" if fields else "replay_model_comparison_unavailable"
    return MappingProxyType(record)


def materialize_replay_model_comparison_record(record: Mapping[str, object]) -> dict[str, object]:
    """Materialize replay model comparison evidence deterministically."""
    if not isinstance(record, Mapping):
        return {"unavailable_reason": "non_mapping_replay_model_comparison", "value_type": no_hook_type_name(record)}
    items, reason = _safe_mapping_items(record)
    if reason:
        return {"unavailable_reason": reason, "value_type": no_hook_type_name(record)}
    out: dict[str, object] = {}
    for key, item in items:
        name = model_contract_safe_text(key)
        out[name] = _materialize_contract_value(item, reason="non_finite_replay_model_comparison_value")
    return out


__all__ = (
    "make_model_snapshot",
    "make_replay_model_comparison_record",
    "materialize_model_snapshot",
    "materialize_replay_model_comparison_record",
)
