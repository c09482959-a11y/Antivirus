"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations


from .constants import MODEL_FAILURE_RECORD_REQUIRED_FIELDS
from .record_validation import invalid_model_failure_record_failure
from .safe_mapping import (
    is_explicit_empty_text,
    json_value,
    mapping_readable,
    safe_mapping_get,
    safe_text_present,
    model_evidence_index_path,
    model_evidence_missing_field_reason,
    model_evidence_is_mapping,
)

def model_failure_record_invalid_reason(value: object) -> str:
    if not model_evidence_is_mapping(value):
        return "non_mapping_model_failure_record"
    if not mapping_readable(value):
        return "unreadable_model_failure_record"
    for required in MODEL_FAILURE_RECORD_REQUIRED_FIELDS:
        if not safe_text_present(safe_mapping_get(value, required)):
            return model_evidence_missing_field_reason(required)
    return ""

def sanitize_model_failure_records(
    source_field: str,
    value: object,
) -> tuple[tuple[object, ...], dict[str, object], tuple[dict[str, object], ...]]:
    if value is None or is_explicit_empty_text(value):
        return (), {}, ()
    values = tuple(value) if type(value) in (list, tuple) else (value,)
    records: list[object] = []
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for index, item in enumerate(values):
        item_source = model_evidence_index_path(source_field, index) if len(values) > 1 else source_field
        reason = model_failure_record_invalid_reason(item)
        if reason:
            unavailable[item_source] = reason
            failures.append(invalid_model_failure_record_failure(item_source, item, reason))
            continue
        records.append(json_value(item))
    return tuple(records), unavailable, tuple(failures)

__all__ = ('model_failure_record_invalid_reason', 'sanitize_model_failure_records')
