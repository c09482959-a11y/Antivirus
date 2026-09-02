"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from .constants import (
    MODEL_FEATURE_PROBABILITY_CONTAINER_FIELDS,
    MODEL_SIGNAL_SOURCE_FIELDS,
)
from .record_validation import invalid_feature_probability_container_failure
from .safe_mapping import (
    is_explicit_empty_text,
    mapping_at,
    mapping_readable,
    safe_mapping_contains,
    safe_mapping_get,
    safe_mapping_keys,
    safe_str,
    model_evidence_child_path,
    model_evidence_index_path,
    model_evidence_is_container,
    model_evidence_is_mapping,
    model_evidence_is_sequence,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def candidate_feature_probability_containers(record: Mapping[str, object]) -> tuple[tuple[str, object], ...]:
    """Return every explicit feature-probability container, valid or malformed.

    ``_feature_probability_sources`` intentionally returns only mapping
    containers because downstream probability projection requires a mapping.
    Invalid-container detection has a different job: if a model signal explicitly
    emitted ``feature_probabilities`` as a list/string/scalar, publication must
    emit degraded evidence instead of dropping that malformed model output.
    """
    candidates: list[tuple[str, object]] = []
    seen_source_names: set[str] = set()

    def add_candidate(source_name: str, value: object) -> None:
        if source_name in seen_source_names:
            return
        seen_source_names.add(source_name)
        candidates.append((source_name, value))

    def visit_nested_signal(source_path: str, value: object) -> None:
        if model_evidence_is_mapping(value):
            keys, reason = safe_mapping_keys(value)
            if reason:
                return
            if safe_mapping_contains(value, "feature_probabilities"):
                add_candidate(
                    model_evidence_child_path(source_path, "feature_probabilities"),
                    safe_mapping_get(value, "feature_probabilities"),
                )
            for raw_key in keys:
                key = safe_str(raw_key)
                if key == "feature_probabilities":
                    continue
                item = safe_mapping_get(value, raw_key)
                if model_evidence_is_container(item):
                    visit_nested_signal(model_evidence_child_path(source_path, key), item)
            return
        if model_evidence_is_sequence(value):
            for index, item in enumerate(value):
                if model_evidence_is_container(item):
                    visit_nested_signal(model_evidence_index_path(source_path, index), item)

    add_candidate("feature_probabilities", safe_mapping_get(record, "feature_probabilities"))
    for metadata_key in MODEL_FEATURE_PROBABILITY_CONTAINER_FIELDS:
        metadata = mapping_at(record, metadata_key)
        add_candidate(model_evidence_child_path(metadata_key, "feature_probabilities"), safe_mapping_get(metadata, "feature_probabilities"))
    for metadata_key in MODEL_SIGNAL_SOURCE_FIELDS:
        if not safe_mapping_contains(record, metadata_key):
            continue
        value = safe_mapping_get(record, metadata_key)
        if model_evidence_is_container(value):
            visit_nested_signal(metadata_key, value)
    model_evidence = mapping_at(record, "model_evidence")
    add_candidate("model_evidence.feature_probabilities", safe_mapping_get(model_evidence, "feature_probabilities"))
    explanation_value = safe_mapping_get(record, "explanation")
    if model_evidence_is_mapping(explanation_value) and not mapping_readable(explanation_value):
        add_candidate("explanation.feature_probabilities", explanation_value)
    else:
        explanation = mapping_at(record, "explanation")
        add_candidate("explanation.feature_probabilities", safe_mapping_get(explanation, "feature_probabilities"))
    return tuple(candidates)

def invalid_feature_probability_container_failures(record: Mapping[str, object]) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for source_field, value in candidate_feature_probability_containers(record):
        if value is None or is_explicit_empty_text(value):
            continue
        if model_evidence_is_mapping(value):
            if not mapping_readable(value):
                reason = "unreadable_feature_probability_record"
                unavailable[source_field] = reason
                failures.append(invalid_feature_probability_container_failure(source_field, value, reason))
            continue
        reason = "non_mapping_feature_probability_record"
        unavailable[source_field] = reason
        failures.append(invalid_feature_probability_container_failure(source_field, value, reason))
    return unavailable, tuple(failures)

__all__ = ('candidate_feature_probability_containers', 'invalid_feature_probability_container_failures')
