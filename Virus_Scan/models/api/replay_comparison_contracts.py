"""Public replay model-evidence comparison contract.

Replay validators compare recorded model evidence against reconstructed evidence
through this canonical boundary.  The comparison freezes caller-owned mappings
before comparing, so replay cannot depend on later live mutable model state.
"""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.api.text_boundary import (
    public_api_contract_text,
    public_blank_mapping_key_label,
    public_duplicate_mapping_key_label,
    public_unreadable_value_label,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from types import MappingProxyType

from Virus_Scan.models.contracts.model_snapshot import (
    make_replay_model_comparison_record,
    materialize_replay_model_comparison_record,
)




def _detached_public_text(value: object) -> str:
    """Return exact built-in text without caller-owned strip/bool hooks."""
    text, _reason = public_api_contract_text(
        value,
        default_text=public_unreadable_value_label(value),
    )
    return text


def _public_reason_text(value: object) -> str | None:
    """Normalize optional public replay reason without truth-testing callers."""
    if value is None:
        return None
    try:
        text = _detached_public_text(value)
    except RECOVERABLE_RUNTIME_ERRORS:
        return "unreadable_replay_model_comparison_reason"
    if text == "":
        return None
    return text


def _first_reason(*values: object) -> str | None:
    for value in values:
        text = _public_reason_text(value)
        if text is not None:
            return text
    return None

def _unreadable_mapping_reason(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    if no_hook_mapping_items(value) is None:
        return "model_evidence_mapping_unreadable"
    return None




def _public_evidence_unavailable(reason: str, value: object) -> dict[str, object]:
    return {
        "ready": False,
        "degraded": True,
        "unavailable_reason": reason,
        "evidence_type": "replay_model_comparison_public_value_unavailable",
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def _freeze_public_evidence_value(value: object) -> object:
    if isinstance(value, Mapping):
        items = no_hook_mapping_items(value)
        if items is None:
            return _public_evidence_unavailable("model_evidence_mapping_unreadable", value)
        out: dict[str, object] = {}
        ordered_items = sorted(items, key=lambda item: _detached_public_text(item[0]))
        for index, (key, child) in enumerate(ordered_items):
            key_text = _detached_public_text(key)
            if key_text == "":
                key_text = public_blank_mapping_key_label(index)
            if key_text in out:
                key_text = public_duplicate_mapping_key_label(key_text, index)
            out[key_text] = _freeze_public_evidence_value(child)
        return out
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_public_evidence_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        try:
            ordered = tuple(sorted(value, key=_detached_public_text))
        except RECOVERABLE_RUNTIME_ERRORS:
            return (_public_evidence_unavailable("model_evidence_set_unreadable", value),)
        return tuple(_freeze_public_evidence_value(item) for item in ordered)
    if isinstance(value, str):
        return str.__str__(_detached_public_text(value))
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text, text_reason = public_api_contract_text(
        value,
        default_text=public_unreadable_value_label(value),
    )
    if text_reason is not None:
        return _public_evidence_unavailable("unreadable_public_contract_text", value)
    return text

def _materialized_mapping(value: object) -> dict[str, object]:
    frozen = _freeze_public_evidence_value(value)
    if not isinstance(frozen, dict):
        return {
            "__unavailable_reason__": "model_evidence_materialization_failed",
            "__value_type__": no_hook_type_name(value),
        }
    try:
        record = make_replay_model_comparison_record(
            model_name="model_evidence_materialization",
            expected=frozen,
            actual=frozen,
            matched=True,
        )
        materialized = materialize_replay_model_comparison_record(record)
    except RECOVERABLE_RUNTIME_ERRORS:
        return {"__unavailable_reason__": "model_evidence_materialization_failed", "__value_type__": no_hook_type_name(value)}
    expected = materialized.get("expected")
    return expected if isinstance(expected, dict) else {}


def _mismatch_fields(expected: object, actual: object) -> tuple[str, ...]:
    if not isinstance(expected, Mapping) or not isinstance(actual, Mapping):
        fields: list[str] = []
        if not isinstance(expected, Mapping):
            fields.append("expected")
        if not isinstance(actual, Mapping):
            fields.append("actual")
        return tuple(fields)
    expected_reason = _unreadable_mapping_reason(expected)
    actual_reason = _unreadable_mapping_reason(actual)
    if expected_reason is not None or actual_reason is not None:
        fields = []
        if expected_reason:
            fields.append("expected")
        if actual_reason:
            fields.append("actual")
        return tuple(fields)
    expected_materialized = _materialized_mapping(expected)
    actual_materialized = _materialized_mapping(actual)
    keys = sorted(set(expected_materialized).union(actual_materialized), key=_detached_public_text)
    missing = object()
    return tuple(
        _detached_public_text(key)
        for key in keys
        if expected_materialized.get(key, missing) != actual_materialized.get(key, missing)
    )


def compare_model_evidence(
    *,
    model_name: object,
    expected: object,
    actual: object,
    reason: object = None,
    model_version: object = "replay_model_evidence_compare_v1",
) -> Mapping[str, object]:
    """Return immutable replay comparison evidence for one model output.

    ``expected`` must be the recorded model evidence and ``actual`` must be the
    reconstructed evidence.  Both are frozen through the canonical replay
    comparison contract before the comparison record is returned.
    """
    fields = _mismatch_fields(expected, actual)
    expected_reason = (
        "non_mapping_replay_expected"
        if not isinstance(expected, Mapping)
        else _unreadable_mapping_reason(expected)
    )
    actual_reason = (
        "non_mapping_replay_actual"
        if not isinstance(actual, Mapping)
        else _unreadable_mapping_reason(actual)
    )
    comparison_reason = _first_reason(reason)
    expected_record = {} if expected_reason or not isinstance(expected, Mapping) else _materialized_mapping(expected)
    actual_record = {} if actual_reason or not isinstance(actual, Mapping) else _materialized_mapping(actual)
    record = dict(make_replay_model_comparison_record(
        model_name=_detached_public_text(model_name),
        expected=expected_record,
        actual=actual_record,
        matched=not fields,
        mismatch_fields=fields,
        reason=comparison_reason,
        model_version=_detached_public_text(model_version),
    ))
    if expected_reason:
        record["expected_unavailable_reason"] = expected_reason
    if actual_reason:
        record["actual_unavailable_reason"] = actual_reason
    return MappingProxyType(record)


def materialize_model_evidence_comparison(record: Mapping[str, object]) -> dict[str, object]:
    """Materialize replay model-evidence comparison deterministically.

    Malformed public contract input is returned as explicit unavailable replay
    comparison evidence instead of raising ``TypeError`` or collapsing to an
    empty clean mapping.
    """
    unavailable_reason = None
    if not isinstance(record, Mapping):
        unavailable_reason = "non_mapping_replay_model_comparison_record"
    else:
        if no_hook_mapping_items(record) is None:
            unavailable_reason = "unreadable_replay_model_comparison_record"
    if unavailable_reason is not None:
        unavailable = make_replay_model_comparison_record(
            model_name="unknown_model",
            expected={},
            actual={},
            matched=False,
            mismatch_fields=("record",),
            reason=unavailable_reason,
            model_version="replay_model_evidence_compare_v1",
        )
        materialized = materialize_replay_model_comparison_record(unavailable)
        materialized["record_unavailable_reason"] = unavailable_reason
        return materialized
    try:
        return materialize_replay_model_comparison_record(record)
    except RECOVERABLE_RUNTIME_ERRORS:
        unavailable = make_replay_model_comparison_record(
            model_name="unknown_model",
            expected={},
            actual={},
            matched=False,
            mismatch_fields=("record",),
            reason="replay_model_comparison_materialization_failed",
            model_version="replay_model_evidence_compare_v1",
        )
        materialized = materialize_replay_model_comparison_record(unavailable)
        materialized["record_unavailable_reason"] = "replay_model_comparison_materialization_failed"
        return materialized


__all__ = (
    "compare_model_evidence",
    "materialize_model_evidence_comparison",
)
