"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from .contract_sanitization_support import sanitize_contract_field
from .probability_validation import probability_record_state_failures
from .record_validation import (
    invalid_contract_record_failure,
    invalid_contract_schema_failure,
    missing_required_contract_fields,
)
from .safe_mapping import (
    json_value,
    mapping_readable,
    safe_mapping_get,
    safe_mapping_keys,
    safe_str,
    model_evidence_child_path,
    model_evidence_index_path,
    model_evidence_unavailable_field,
    model_evidence_is_mapping,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def _contract_mapping(value: object) -> Mapping[str, object] | None:
    if model_evidence_is_mapping(value):
        return value
    return None


def _contract_sequence_items(value: object) -> tuple[object, ...] | None:
    if type(value) is tuple:
        return value
    if type(value) is list:
        return tuple(value)
    return None


def sanitize_contract_mapping(
    source_container: str,
    value: Mapping[str, object],
    *,
    path: str = "",
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    out: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    keys, read_reason = safe_mapping_keys(value)
    if read_reason:
        metric_path = path or source_container
        unavailable[model_evidence_child_path(source_container, metric_path)] = read_reason
        failures.append(invalid_contract_schema_failure(source_container, metric_path, read_reason))
        return out, unavailable, tuple(failures)
    for raw_key in keys:
        key = safe_str(raw_key)
        metric_path = model_evidence_child_path(path, key)
        item = safe_mapping_get(value, raw_key)
        field = sanitize_contract_field(source_container, key, item, metric_path)
        if field.handled:
            out.update(field.values)
            unavailable.update(field.unavailable)
            failures.extend(field.failures)
            continue
        item_mapping = _contract_mapping(item)
        if item_mapping is not None:
            child, child_unavailable, child_failures = sanitize_contract_mapping(
                source_container,
                item_mapping,
                path=metric_path,
            )
            out[key] = child
            unavailable.update(child_unavailable)
            failures.extend(child_failures)
            continue
        item_sequence = _contract_sequence_items(item)
        if item_sequence is not None:
            normalized_items: list[object] = []
            for index, child_item in enumerate(item_sequence):
                child_mapping = _contract_mapping(child_item)
                if child_mapping is not None:
                    child, child_unavailable, child_failures = sanitize_contract_mapping(
                        source_container,
                        child_mapping,
                        path=model_evidence_index_path(metric_path, index),
                    )
                    normalized_items.append(child)
                    unavailable.update(child_unavailable)
                    failures.extend(child_failures)
                else:
                    normalized_items.append(json_value(child_item))
            out[key] = tuple(normalized_items)
            continue
        out[key] = json_value(item)
    return out, unavailable, tuple(failures)

def sanitize_contract_record(
    source_container: str,
    value: object,
) -> tuple[object, dict[str, object], tuple[dict[str, object], ...]]:
    if not model_evidence_is_mapping(value):
        reason = "non_mapping_model_contract_record"
        return (
            None,
            {source_container: reason},
            (invalid_contract_record_failure(source_container, value, reason),),
        )
    if not mapping_readable(value):
        reason = "unreadable_model_contract_record"
        return (
            None,
            {source_container: reason},
            (invalid_contract_record_failure(source_container, value, reason),),
        )
    missing_unavailable, missing_failures = missing_required_contract_fields(source_container, value)
    sanitized, unavailable, failures = sanitize_contract_mapping(source_container, value)
    for missing_field, missing_reason in missing_unavailable.items():
        terminal = missing_field.rsplit('.', 1)[-1]
        sanitized.setdefault(model_evidence_unavailable_field(terminal), missing_reason)
    unavailable.update(missing_unavailable)
    state_unavailable, state_failures = probability_record_state_failures(source_container, value, sanitized)
    unavailable.update(state_unavailable)
    return sanitized, unavailable, failures + missing_failures + state_failures

__all__ = ('sanitize_contract_mapping', 'sanitize_contract_record')
