"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from .constants import (
    MODEL_FAILURE_RECORD_KEYS,
    MODEL_SIGNAL_SOURCE_FIELDS,
)
from .model_failure_sanitization import (
    sanitize_model_failure_records,
)
from .record_validation import invalid_model_failure_record_failure
from .safe_mapping import (
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

def model_failure_records(
    feature_probabilities: Mapping[str, object],
    *,
    source_field: str = "feature_probabilities",
) -> tuple[tuple[object, ...], dict[str, object], tuple[dict[str, object], ...]]:
    records: list[object] = []
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for field in MODEL_FAILURE_RECORD_KEYS:
        if not safe_mapping_contains(feature_probabilities, field):
            continue
        field_records, field_unavailable, field_failures = sanitize_model_failure_records(
            model_evidence_child_path(source_field, field),
            safe_mapping_get(feature_probabilities, field),
        )
        records.extend(field_records)
        unavailable.update(field_unavailable)
        failures.extend(field_failures)
    return tuple(records), unavailable, tuple(failures)

def existing_failure_records(
    evidence: Mapping[str, object],
) -> tuple[tuple[object, ...], dict[str, object], tuple[dict[str, object], ...]]:
    records: list[object] = []
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for field in ("model_failure", "model_failure_record", "model_failures"):
        if not safe_mapping_contains(evidence, field):
            continue
        field_records, field_unavailable, field_failures = sanitize_model_failure_records(
            model_evidence_child_path("model_evidence", field),
            safe_mapping_get(evidence, field),
        )
        records.extend(field_records)
        unavailable.update(field_unavailable)
        failures.extend(field_failures)
    return tuple(records), unavailable, tuple(failures)

def direct_model_failure_records(
    record: Mapping[str, object],
) -> tuple[tuple[object, ...], dict[str, object], tuple[dict[str, object], ...]]:
    records: list[object] = []
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for field in ("model_failure", "model_failure_record", "model_failures"):
        if not safe_mapping_contains(record, field):
            continue
        field_records, field_unavailable, field_failures = sanitize_model_failure_records(field, safe_mapping_get(record, field))
        records.extend(field_records)
        unavailable.update(field_unavailable)
        failures.extend(field_failures)
    return tuple(records), unavailable, tuple(failures)

def nested_model_signal_failure_records(
    record: Mapping[str, object],
) -> tuple[tuple[object, ...], dict[str, object], tuple[dict[str, object], ...]]:
    """Project model-failure evidence nested inside model signal containers.

    Model signals may be carried under adaptive_learning/model_context/layered
    metadata instead of directly in feature_probabilities.  Publication must not
    drop those output-affecting failure records merely because the containing
    mapping is not the primary probability source.
    """
    records: list[object] = []
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    seen_paths: set[str] = set()

    def visit(source_path: str, value: object) -> None:
        if model_evidence_is_mapping(value):
            keys, read_reason = safe_mapping_keys(value)
            if read_reason:
                unavailable[source_path] = read_reason
                failures.append(invalid_model_failure_record_failure(source_path, value, read_reason))
                return
            for failure_key in MODEL_FAILURE_RECORD_KEYS:
                if not safe_mapping_contains(value, failure_key):
                    continue
                failure_path = model_evidence_child_path(source_path, failure_key)
                if failure_path in seen_paths:
                    continue
                seen_paths.add(failure_path)
                field_records, field_unavailable, field_failures = sanitize_model_failure_records(
                    failure_path,
                    safe_mapping_get(value, failure_key),
                )
                records.extend(field_records)
                unavailable.update(field_unavailable)
                failures.extend(field_failures)
            for raw_key in keys:
                key = safe_str(raw_key)
                if key in MODEL_FAILURE_RECORD_KEYS or key == "feature_probabilities":
                    continue
                item = safe_mapping_get(value, raw_key)
                if model_evidence_is_container(item):
                    child_path = model_evidence_child_path(source_path, key)
                    visit(child_path, item)
            return
        if model_evidence_is_sequence(value):
            for index, item in enumerate(value):
                if model_evidence_is_container(item):
                    visit(model_evidence_index_path(source_path, index), item)

    for field in MODEL_SIGNAL_SOURCE_FIELDS:
        if not safe_mapping_contains(record, field):
            continue
        value = safe_mapping_get(record, field)
        if model_evidence_is_container(value):
            visit(field, value)
    return tuple(records), unavailable, tuple(failures)

__all__ = ('direct_model_failure_records', 'existing_failure_records', 'model_failure_records', 'nested_model_signal_failure_records')
