"""Assembly helpers for publication model-evidence projection."""

from __future__ import annotations
from typing import TYPE_CHECKING


from .constants import MODEL_EVIDENCE_WRITER_VERSION, MODEL_CONTRACT_RECORD_FIELDS
from .container_candidates import invalid_feature_probability_container_failures
from .contract_records import (
    direct_model_contract_records,
    existing_model_contract_failure_records,
    existing_model_contract_records,
    has_replay_model_mismatch_evidence,
    nested_model_signal_contract_records,
)
from .existing_evidence import (
    feature_probability_extra_field_evidence,
    json_existing_model_evidence_mapping,
    merge_mapping,
    sanitize_existing_feature_probabilities,
)
from .failure_projection import (
    direct_model_failure_records,
    existing_failure_records,
    model_failure_records,
    nested_model_signal_failure_records,
)
from .nonfinite import (
    contains_non_finite_existing_model_payload,
    invalid_model_signal_failures,
)
from .probability_projection import (
    probability_fields,
    secondary_probability_failures,
    secondary_probability_fields,
)
from .record_validation import invalid_model_evidence_record_failure
from .safe_mapping import (
    is_explicit_empty_text,
    mapping_readable,
    safe_mapping_get,
    safe_mapping_keys,
    model_evidence_is_mapping,
)
from .sources import feature_probability_source_with_name
from .unavailable_projection import (
    nested_model_signal_unavailable_reasons,
    sanitize_existing_unavailable_reasons_record,
    secondary_unavailable_reasons,
    unavailable_reasons,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def _mapping_has_entries(value: Mapping[str, object] | None) -> bool:
    if value is None:
        return False
    keys, reason = safe_mapping_keys(value)
    return not reason and len(keys) > 0

def _flag_enabled(value: object) -> bool:
    return value is True

def merge_many(*mappings: Mapping[str, object] | None) -> dict[str, object]:
    merged: dict[str, object] = {}
    for mapping in mappings:
        if mapping is not None and _mapping_has_entries(mapping):
            merged = merge_mapping(merged, mapping)
    return merged

def existing_evidence_base(existing_evidence: object) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    if model_evidence_is_mapping(existing_evidence) and mapping_readable(existing_evidence):
        evidence = json_existing_model_evidence_mapping(existing_evidence)
        if contains_non_finite_existing_model_payload(existing_evidence):
            return evidence, {"model_evidence": "non_finite_model_evidence_value"}, (
                invalid_model_evidence_record_failure(existing_evidence, "non_finite_model_evidence_value"),
            )
        return evidence, {}, ()
    if existing_evidence is None or is_explicit_empty_text(existing_evidence):
        return {}, {}, ()
    reason = "unreadable_model_evidence_record" if model_evidence_is_mapping(existing_evidence) else "non_mapping_model_evidence_record"
    return {}, {"model_evidence": reason}, (invalid_model_evidence_record_failure(existing_evidence, reason),)

def sanitize_existing_probability_field(evidence: dict[str, object]) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    if "feature_probabilities" not in evidence:
        return {}, ()
    sanitized, unavailable, failures = sanitize_existing_feature_probabilities(evidence.get("feature_probabilities"))
    if sanitized:
        evidence["feature_probabilities"] = sanitized
    else:
        evidence.pop("feature_probabilities", None)
    return unavailable, failures

def sanitize_existing_unavailable_field(evidence: dict[str, object]) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    if "unavailable_reasons" not in evidence:
        return {}, ()
    sanitized, unavailable, failures = sanitize_existing_unavailable_reasons_record(evidence.get("unavailable_reasons"))
    if sanitized:
        evidence["unavailable_reasons"] = sanitized
    else:
        evidence.pop("unavailable_reasons", None)
    return unavailable, failures

def apply_existing_contract_records(evidence: dict[str, object]) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    records, unavailable, failures = existing_model_contract_records(evidence)
    for field in MODEL_CONTRACT_RECORD_FIELDS:
        if field in unavailable and field not in records:
            evidence.pop(field, None)
    evidence.update(records)
    return unavailable, failures

def existing_evidence_projection(existing_evidence: object) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    evidence, unavailable, failures = existing_evidence_base(existing_evidence)
    feature_unavailable, feature_failures = sanitize_existing_probability_field(evidence)
    reason_unavailable, reason_failures = sanitize_existing_unavailable_field(evidence)
    contract_unavailable, contract_failures = apply_existing_contract_records(evidence)
    return evidence, merge_many(unavailable, feature_unavailable, reason_unavailable, contract_unavailable), (
        failures + feature_failures + reason_failures + contract_failures
    )

def probability_projection_parts(
    record: Mapping[str, object],
    *,
    primary_source_name: str,
    feature_probabilities: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    probabilities, invalid_reasons, invalid_failures = probability_fields(feature_probabilities)
    secondary_probabilities = secondary_probability_fields(
        record,
        primary_source_name=primary_source_name,
        primary_feature_probabilities=feature_probabilities,
    )
    secondary_reasons, secondary_failures = secondary_probability_failures(record, primary_source_name=primary_source_name)
    container_unavailable, container_failures = invalid_feature_probability_container_failures(record)
    signal_failures = invalid_model_signal_failures(record)
    signal_unavailable = {failure["affected_fields"][0]: failure["reason"] for failure in signal_failures}
    extra_unavailable, extra_failures = feature_probability_extra_field_evidence(record, primary_source_name=primary_source_name)
    return merge_mapping(secondary_probabilities, probabilities), merge_many(
        invalid_reasons,
        secondary_reasons,
        container_unavailable,
        signal_unavailable,
        extra_unavailable,
    ), (
        invalid_failures
        + secondary_failures
        + container_failures
        + signal_failures
        + extra_failures
    )

def failure_projection_parts(
    record: Mapping[str, object],
    *,
    evidence: dict[str, object],
    primary_source_name: str,
    feature_probabilities: Mapping[str, object],
) -> tuple[tuple[dict[str, object], ...], dict[str, object], tuple[dict[str, object], ...]]:
    probability_failures, probability_unavailable, invalid_probability_records = model_failure_records(
        feature_probabilities,
        source_field=primary_source_name or "feature_probabilities",
    )
    direct_failures, direct_unavailable, invalid_direct_records = direct_model_failure_records(record)
    nested_failures, nested_unavailable, invalid_nested_records = nested_model_signal_failure_records(record)
    existing_failures, existing_unavailable, invalid_existing_records = existing_failure_records(evidence)
    existing_contract_failures, contract_unavailable, invalid_contract_records = existing_model_contract_failure_records(evidence)
    for failure_field in ("model_failure", "model_failure_record", "model_failures"):
        evidence.pop(failure_field, None)
    return existing_failures, merge_many(
        probability_unavailable,
        direct_unavailable,
        nested_unavailable,
        existing_unavailable,
        contract_unavailable,
    ), (
        probability_failures
        + direct_failures
        + nested_failures
        + existing_contract_failures
        + invalid_probability_records
        + invalid_direct_records
        + invalid_nested_records
        + invalid_existing_records
        + invalid_contract_records
    )

def unavailable_projection_parts(
    record: Mapping[str, object],
    *,
    primary_source_name: str,
    feature_probabilities: Mapping[str, object],
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    feature_reasons, feature_unavailable, feature_failures = unavailable_reasons(
        feature_probabilities,
        source_name=primary_source_name or "feature_probabilities",
    )
    secondary_reasons, secondary_unavailable, secondary_failures = secondary_unavailable_reasons(
        record,
        primary_source_name=primary_source_name,
    )
    nested_reasons, nested_unavailable, nested_failures = nested_model_signal_unavailable_reasons(record)
    return merge_many(
        feature_reasons,
        secondary_reasons,
        nested_reasons,
        feature_unavailable,
        secondary_unavailable,
        nested_unavailable,
    ), feature_failures + secondary_failures + nested_failures

def contract_projection_parts(record: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    direct_records, direct_unavailable, direct_failures = direct_model_contract_records(record)
    nested_records, nested_unavailable, nested_failures = nested_model_signal_contract_records(record)
    return direct_records, nested_records, merge_many(direct_unavailable, nested_unavailable), direct_failures + nested_failures

def apply_projected_records(
    evidence: dict[str, object],
    *,
    direct_contract_records: Mapping[str, object],
    nested_contract_records: Mapping[str, object],
    projected_probabilities: Mapping[str, object],
    unavailable: Mapping[str, object],
    existing_failures: tuple[dict[str, object], ...],
    failures: tuple[dict[str, object], ...],
) -> None:
    for field, value in direct_contract_records.items():
        evidence.setdefault(field, value)
    for field, value in nested_contract_records.items():
        evidence.setdefault(field, value)
    if _mapping_has_entries(projected_probabilities):
        evidence["feature_probabilities"] = merge_mapping(evidence.get("feature_probabilities"), projected_probabilities)
    if _mapping_has_entries(unavailable):
        evidence["unavailable_reasons"] = merge_mapping(evidence.get("unavailable_reasons"), unavailable)
    if failures:
        evidence["model_failures"] = existing_failures + failures
    elif existing_failures:
        evidence["model_failures"] = existing_failures

def final_model_evidence_fields(evidence: dict[str, object]) -> dict[str, object]:
    fields: dict[str, object] = {}
    if _mapping_has_entries(evidence):
        evidence.setdefault("writer_version", MODEL_EVIDENCE_WRITER_VERSION)
        has_failure_evidence = (
            "model_failures" in evidence
            or "unavailable_reasons" in evidence
        )
        has_replay_mismatch_evidence = has_replay_model_mismatch_evidence(evidence)
        must_record = has_failure_evidence or has_replay_mismatch_evidence
        evidence["final_json_must_record"] = _flag_enabled(evidence.get("final_json_must_record")) or must_record
        evidence["replay_record_required"] = _flag_enabled(evidence.get("replay_record_required")) or must_record
        fields["model_evidence"] = evidence
    return fields

def build_model_evidence_final_json_fields(record: Mapping[str, object]) -> dict[str, object]:
    primary_source_name, feature_probabilities = feature_probability_source_with_name(record)
    existing_model_evidence = safe_mapping_get(record, "model_evidence")
    evidence, existing_unavailable, existing_failures = existing_evidence_projection(existing_model_evidence)
    projected_probabilities, probability_unavailable, probability_failures = probability_projection_parts(
        record,
        primary_source_name=primary_source_name,
        feature_probabilities=feature_probabilities,
    )
    existing_failure_record_values, failure_unavailable, failure_records = failure_projection_parts(
        record,
        evidence=evidence,
        primary_source_name=primary_source_name,
        feature_probabilities=feature_probabilities,
    )
    projected_unavailable_reasons, unavailable_failures = unavailable_projection_parts(
        record,
        primary_source_name=primary_source_name,
        feature_probabilities=feature_probabilities,
    )
    direct_contract_records, nested_contract_records, contract_unavailable, contract_failures = contract_projection_parts(record)
    unavailable = merge_many(existing_unavailable, probability_unavailable, failure_unavailable, projected_unavailable_reasons, contract_unavailable)
    failures = existing_failures + probability_failures + failure_records + unavailable_failures + contract_failures
    apply_projected_records(
        evidence,
        direct_contract_records=direct_contract_records,
        nested_contract_records=nested_contract_records,
        projected_probabilities=projected_probabilities,
        unavailable=unavailable,
        existing_failures=existing_failure_record_values,
        failures=failures,
    )
    return final_model_evidence_fields(evidence)

__all__ = ('apply_existing_contract_records', 'apply_projected_records', 'build_model_evidence_final_json_fields', 'contract_projection_parts', 'existing_evidence_base', 'existing_evidence_projection', 'failure_projection_parts', 'final_model_evidence_fields', 'merge_many', 'probability_projection_parts', 'sanitize_existing_probability_field', 'sanitize_existing_unavailable_field', 'unavailable_projection_parts')
