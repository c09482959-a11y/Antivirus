"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

from .probability_validation import invalid_probability_failure
from .constants import (
    MODEL_EVIDENCE_WRITER_VERSION,
    MODEL_PROBABILITY_RECORD_KEYS,
    MODEL_PROBABILITY_RECORD_REQUIRED_FIELDS,
    MODEL_REPLAY_COMPARISON_RECORD_KEYS,
    MODEL_REPLAY_COMPARISON_RECORD_REQUIRED_FIELDS,
)
from .safe_mapping import (
    safe_mapping_contains,
    safe_repr,
    safe_str,
    model_evidence_child_path,
    model_evidence_unavailable_field,
    model_evidence_is_mapping,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def contract_record_terminal_name(field_name: object) -> str:
    return safe_str(field_name if field_name is not None else "").strip().split(".")[-1]

def required_contract_record_fields(field_name: object) -> tuple[str, ...]:
    terminal = contract_record_terminal_name(field_name)
    if terminal in MODEL_PROBABILITY_RECORD_KEYS:
        return MODEL_PROBABILITY_RECORD_REQUIRED_FIELDS
    if terminal in MODEL_REPLAY_COMPARISON_RECORD_KEYS:
        return MODEL_REPLAY_COMPARISON_RECORD_REQUIRED_FIELDS
    return ()

def missing_required_contract_field_reason(field_name: object) -> str:
    terminal = contract_record_terminal_name(field_name)
    if terminal in MODEL_REPLAY_COMPARISON_RECORD_KEYS:
        return "missing_replay_model_comparison_field"
    return "missing_probability_record_field"

def is_replay_comparison_record_container(field_name: object) -> bool:
    return contract_record_terminal_name(field_name) in MODEL_REPLAY_COMPARISON_RECORD_KEYS

def valid_replay_mismatch_fields(value: object) -> tuple[tuple[str, ...], str]:
    if isinstance(value, (str, bytes)) or model_evidence_is_mapping(value):
        return (), "non_sequence_replay_mismatch_fields"
    if type(value) not in (list, tuple, set, frozenset):
        return (), "non_sequence_replay_mismatch_fields"
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return (), "non_text_replay_mismatch_field"
        text = safe_str(item).strip()
        if text == "":
            return (), "blank_replay_mismatch_field"
        normalized.append(text)
    return tuple(sorted(normalized, key=str)), ""

def invalid_contract_schema_failure(source_container: str, metric_path: str, reason: str) -> dict[str, object]:
    return {
        "model_name": model_evidence_child_path(source_container, metric_path),
        "failure_type": "invalid_model_contract_record_schema",
        "reason": reason,
        "affected_fields": (source_container, metric_path),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_container": source_container,
            "source_field": metric_path,
        },
    }

def missing_required_contract_fields(
    source_container: str,
    value: Mapping[str, object],
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for field in required_contract_record_fields(source_container):
        if safe_mapping_contains(value, field) or safe_mapping_contains(value, model_evidence_unavailable_field(field)):
            continue
        reason = missing_required_contract_field_reason(source_container)
        unavailable[model_evidence_child_path(source_container, field)] = reason
        failures.append(invalid_contract_schema_failure(source_container, field, reason))
    return unavailable, tuple(failures)

def invalid_contract_record_failure(source_container: str, value: object, reason: str) -> dict[str, object]:
    failure = invalid_probability_failure(source_container, value, reason)
    failure["model_name"] = source_container
    failure["affected_fields"] = (source_container,)
    failure["details"] = {
        **failure.get("details", {}),
        "source_container": source_container,
        "source_field": source_container,
    }
    return failure

def invalid_model_failure_record_failure(source_field: str, value: object, reason: str) -> dict[str, object]:
    return {
        "model_name": source_field,
        "failure_type": "invalid_model_failure_record",
        "reason": reason,
        "affected_fields": (source_field,),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_field": source_field,
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

def invalid_model_evidence_record_failure(value: object, reason: str) -> dict[str, object]:
    return {
        "model_name": "model_evidence",
        "failure_type": "invalid_model_evidence_record",
        "reason": reason,
        "affected_fields": ("model_evidence",),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_field": "model_evidence",
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

def invalid_model_unavailable_reasons_record_failure(
    value: object,
    reason: str,
    *,
    source_field: str = "model_evidence.unavailable_reasons",
) -> dict[str, object]:
    return {
        "model_name": source_field,
        "failure_type": "invalid_model_unavailable_reasons_record",
        "reason": reason,
        "affected_fields": (source_field,),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_field": source_field,
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

def invalid_feature_probability_container_failure(source_field: str, value: object, reason: str) -> dict[str, object]:
    return {
        "model_name": source_field,
        "failure_type": "invalid_feature_probability_record",
        "reason": reason,
        "affected_fields": (source_field,),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_field": source_field,
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

def invalid_existing_feature_probability_field_failure(source_field: str, value: object, reason: str) -> dict[str, object]:
    return {
        "model_name": source_field,
        "failure_type": "invalid_existing_feature_probability_field",
        "reason": reason,
        "affected_fields": (source_field,),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_field": source_field,
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

__all__ = ('contract_record_terminal_name', 'invalid_contract_record_failure', 'invalid_contract_schema_failure', 'invalid_existing_feature_probability_field_failure', 'invalid_feature_probability_container_failure', 'invalid_model_evidence_record_failure', 'invalid_model_failure_record_failure', 'invalid_model_unavailable_reasons_record_failure', 'is_replay_comparison_record_container', 'missing_required_contract_field_reason', 'missing_required_contract_fields', 'required_contract_record_fields', 'valid_replay_mismatch_fields')
