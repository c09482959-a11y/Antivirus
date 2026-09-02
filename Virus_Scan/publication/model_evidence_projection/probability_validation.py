"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

from .constants import (
    MODEL_EVIDENCE_WRITER_VERSION,
    MODEL_CONTRACT_BOOLEAN_FLAG_FIELDS,
    MODEL_CONTRACT_NONNEGATIVE_INTEGER_FIELDS,
    MODEL_CONTRACT_PROBABILITY_FIELD_EXCLUSIONS,
    MODEL_CONTRACT_PROBABILITY_MAPPING_FIELDS,
    MODEL_CONTRACT_SCALAR_PROBABILITY_FIELDS,
    MODEL_PROBABILITY_RECORD_KEYS,
    MODEL_PROBABILITY_RECORD_REQUIRED_TEXT_FIELDS,
)
from .safe_mapping import (
    safe_repr,
    safe_str,
    safe_text_present,
    model_evidence_child_path,
    model_evidence_probability_model_name,
    model_evidence_unavailable_field,
    model_evidence_non_boolean_flag_reason,
    model_evidence_is_mapping,
    model_evidence_is_sequence,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def contract_record_terminal_name(field_name: object) -> str:
    return safe_str(field_name).rsplit(".", 1)[-1]

def valid_probability(value: object) -> tuple[bool, float | None, str]:
    if type(value) is int:
        probability = value / 1.0
    elif type(value) is float:
        probability = value
    else:
        return False, None, "non_numeric_probability"
    if not math.isfinite(probability):
        return False, None, "non_finite_probability"
    if probability < 0.0 or probability > 1.0:
        return False, None, "out_of_bounds_probability"
    return True, probability, ""

def invalid_probability_failure(field: str, value: object, reason: str) -> dict[str, object]:
    return {
        "model_name": model_evidence_probability_model_name(field),
        "failure_type": "invalid_model_probability",
        "reason": reason,
        "affected_fields": (field,),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_field": field,
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

def invalid_contract_probability_failure(source_field: str, value: object, reason: str) -> dict[str, object]:
    failure = invalid_probability_failure(source_field, value, reason)
    failure["model_name"] = model_evidence_child_path(source_field, "probability")
    failure["affected_fields"] = (source_field, "probability")
    failure["details"] = {
        **failure.get("details", {}),
        "source_container": source_field,
        "source_field": "probability",
    }
    return failure

def is_probability_record_container(field_name: object) -> bool:
    return contract_record_terminal_name(field_name) in MODEL_PROBABILITY_RECORD_KEYS

def valid_probability_record_text(value: object) -> tuple[bool, str]:
    if not isinstance(value, str):
        return False, "non_text_probability_record_field"
    if safe_str(value).strip() == "":
        return False, "blank_probability_record_field"
    return True, ""

def valid_probability_identity_text(value: object) -> tuple[bool, str]:
    if not isinstance(value, str):
        return False, "non_text_probability_record_identity"
    if safe_str(value).strip() == "":
        return False, "blank_probability_record_identity"
    return True, ""

def valid_probability_flow(value: object) -> tuple[tuple[str, ...], str]:
    if value is None:
        return (), ""
    if isinstance(value, (str, bytes)) or model_evidence_is_mapping(value):
        return (), "non_sequence_probability_record_flow"
    if not model_evidence_is_sequence(value):
        return (), "non_sequence_probability_record_flow"
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return (), "non_text_probability_record_flow_item"
        text = safe_str(item).strip()
        if text == "":
            return (), "blank_probability_record_flow_item"
        normalized.append(text)
    return tuple(normalized), ""


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

def probability_record_state_failures(
    source_container: str,
    value: Mapping[str, object],
    sanitized: dict[str, object],
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    del value  # Explicitly unused contract parameters.
    if contract_record_terminal_name(source_container) not in MODEL_PROBABILITY_RECORD_KEYS:
        return {}, ()
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for text_field in MODEL_PROBABILITY_RECORD_REQUIRED_TEXT_FIELDS:
        if text_field not in sanitized or model_evidence_unavailable_field(text_field) in sanitized:
            continue
        valid_text, reason = valid_probability_record_text(sanitized.get(text_field))
        if not valid_text:
            sanitized.pop(text_field, None)
            sanitized[model_evidence_unavailable_field(text_field)] = reason
            unavailable[model_evidence_child_path(source_container, text_field)] = reason
            failures.append(invalid_contract_schema_failure(source_container, text_field, reason))
    provenance_unavailable = tuple(
        field
        for field in ("source", "target", "flow")
        if model_evidence_unavailable_field(field) in sanitized
    )
    if provenance_unavailable and "probability_unavailable_reason" not in sanitized:
        reason_value = sanitized.get(model_evidence_unavailable_field(provenance_unavailable[0]))
        reason = safe_str(reason_value).strip() if safe_text_present(reason_value) else "invalid_probability_record_provenance"
        sanitized.pop("probability", None)
        sanitized["probability_unavailable_reason"] = reason
        unavailable[model_evidence_child_path(source_container, "probability")] = reason
        failures.append(invalid_contract_schema_failure(source_container, "probability", reason))
    if "ready" not in sanitized or "ready_unavailable_reason" in sanitized:
        return unavailable, tuple(failures)
    ready = sanitized.get("ready")
    if not isinstance(ready, bool):
        return unavailable, tuple(failures)
    probability_missing = "probability" not in sanitized or sanitized.get("probability") is None
    if ready and probability_missing and "probability_unavailable_reason" not in sanitized:
        reason = "ready_probability_missing"
        sanitized.pop("ready", None)
        sanitized["ready_unavailable_reason"] = reason
        sanitized.pop("probability", None)
        sanitized["probability_unavailable_reason"] = reason
        unavailable[model_evidence_child_path(source_container, "ready")] = reason
        unavailable[model_evidence_child_path(source_container, "probability")] = reason
        failures.append(invalid_contract_schema_failure(source_container, "ready", reason))
        failures.append(invalid_contract_schema_failure(source_container, "probability", reason))
    if not ready and sanitized.get("probability") is not None:
        reason = "not_ready_probability_present"
        sanitized.pop("probability", None)
        sanitized["probability_unavailable_reason"] = reason
        unavailable[model_evidence_child_path(source_container, "probability")] = reason
        failures.append(invalid_contract_schema_failure(source_container, "probability", reason))
    reason_missing = not safe_text_present(sanitized.get("reason"))
    if not ready and reason_missing and "reason_unavailable_reason" not in sanitized:
        reason = "not_ready_reason_missing"
        sanitized.pop("reason", None)
        sanitized["reason_unavailable_reason"] = reason
        unavailable[model_evidence_child_path(source_container, "reason")] = reason
        failures.append(invalid_contract_schema_failure(source_container, "reason", reason))
    return unavailable, tuple(failures)

def is_contract_scalar_probability_field(field_name: object) -> bool:
    name = safe_str(field_name if field_name is not None else "").strip().lower()
    if not name:
        return False
    if name in MODEL_CONTRACT_SCALAR_PROBABILITY_FIELDS:
        return True
    if name.endswith("_confidence") and not name.endswith("_confidence_amplifier"):
        return True
    if not name.endswith("_probability"):
        return False
    return name not in MODEL_CONTRACT_PROBABILITY_FIELD_EXCLUSIONS

def is_contract_probability_mapping_field(field_name: object) -> bool:
    name = safe_str(field_name if field_name is not None else "").strip().lower()
    return name in MODEL_CONTRACT_PROBABILITY_MAPPING_FIELDS or name.endswith("_probabilities")

def is_contract_nonnegative_integer_field(field_name: object) -> bool:
    name = safe_str(field_name if field_name is not None else "").strip().lower()
    return (
        name in MODEL_CONTRACT_NONNEGATIVE_INTEGER_FIELDS
        or name.endswith(("_support", "_count", "_vocab"))
    )

def is_contract_boolean_flag_field(field_name: object) -> bool:
    name = safe_str(field_name if field_name is not None else "").strip().lower()
    return name in MODEL_CONTRACT_BOOLEAN_FLAG_FIELDS or name.endswith("_ready")

def is_contract_unavailable_reason_field(field_name: object) -> bool:
    return safe_str(field_name if field_name is not None else "").strip().lower().endswith("_unavailable_reason")

def contract_unavailable_reason_target(metric_path: str) -> str:
    return metric_path.removesuffix("_unavailable_reason")

def valid_boolean_flag(value: object, *, field_name: str = "readiness") -> tuple[bool, bool | None, str]:
    if value is None:
        return True, None, ""
    if not isinstance(value, bool):
        return False, None, model_evidence_non_boolean_flag_reason(field_name)
    return True, value, ""

def valid_nonnegative_integer_metric(value: object) -> tuple[bool, int | None, str]:
    if value is None:
        return True, None, ""
    if type(value) is int:
        metric = value / 1.0
    elif type(value) is float:
        metric = value
    else:
        return False, None, "non_numeric_count_support_metric"
    if not math.isfinite(metric):
        return False, None, "non_finite_count_support_metric"
    if metric < 0.0:
        return False, None, "negative_count_support_metric"
    if not metric.is_integer():
        return False, None, "non_integer_count_support_metric"
    return True, int(metric), ""

def invalid_contract_metric_failure(source_container: str, metric_path: str, value: object, reason: str) -> dict[str, object]:
    failure = invalid_probability_failure(metric_path, value, reason)
    failure["model_name"] = model_evidence_child_path(source_container, metric_path)
    failure["affected_fields"] = (source_container, metric_path)
    failure["details"] = {
        **failure.get("details", {}),
        "source_container": source_container,
        "source_field": metric_path,
    }
    return failure

def invalid_contract_count_metric_failure(source_container: str, metric_path: str, value: object, reason: str) -> dict[str, object]:
    return {
        "model_name": model_evidence_child_path(source_container, metric_path),
        "failure_type": "invalid_model_count_support_metric",
        "reason": reason,
        "affected_fields": (source_container, metric_path),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_container": source_container,
            "source_field": metric_path,
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

def invalid_contract_readiness_flag_failure(source_container: str, metric_path: str, value: object, reason: str) -> dict[str, object]:
    return {
        "model_name": model_evidence_child_path(source_container, metric_path),
        "failure_type": "invalid_model_readiness_flag",
        "reason": reason,
        "affected_fields": (source_container, metric_path),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_container": source_container,
            "source_field": metric_path,
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

__all__ = ('contract_record_terminal_name', 'contract_unavailable_reason_target', 'invalid_contract_count_metric_failure', 'invalid_contract_metric_failure', 'invalid_contract_probability_failure', 'invalid_contract_readiness_flag_failure', 'invalid_contract_schema_failure', 'invalid_probability_failure', 'is_contract_boolean_flag_field', 'is_contract_nonnegative_integer_field', 'is_contract_probability_mapping_field', 'is_contract_scalar_probability_field', 'is_contract_unavailable_reason_field', 'is_probability_record_container', 'probability_record_state_failures', 'valid_boolean_flag', 'valid_nonnegative_integer_metric', 'valid_probability', 'valid_probability_flow', 'valid_probability_identity_text', 'valid_probability_record_text')
