"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

from .constants import (
    MODEL_EVIDENCE_WRITER_VERSION,
    MODEL_FAILURE_RECORD_KEYS,
    MODEL_SIGNAL_SOURCE_FIELDS,
)
from .record_validation import (
    invalid_model_unavailable_reasons_record_failure,
)
from .safe_mapping import (
    is_explicit_empty_text,
    safe_mapping_contains,
    safe_mapping_get,
    safe_mapping_keys,
    safe_repr,
    safe_str,
    safe_text_result,
    model_evidence_child_path,
    model_evidence_index_path,
    model_evidence_type_marker,
    model_evidence_is_container,
    model_evidence_is_mapping,
    model_evidence_is_sequence,
)
from .sources import feature_probability_sources

if TYPE_CHECKING:
    from collections.abc import Mapping

def feature_unavailable_reason_failure(source_field: str, value: object, reason: str) -> dict[str, object]:
    return {
        "model_name": source_field,
        "failure_type": "invalid_model_unavailable_reason",
        "reason": reason,
        "affected_fields": (source_field,),
        "model_version": MODEL_EVIDENCE_WRITER_VERSION,
        "details": {
            "source_field": source_field,
            "value_type": no_hook_type_name(value),
            "value_repr": safe_repr(value),
        },
    }

def unavailable_reasons(
    feature_probabilities: Mapping[str, object],
    *,
    source_name: str = "feature_probabilities",
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    reasons: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    keys, read_reason = safe_mapping_keys(feature_probabilities)
    if read_reason != '':
        unavailable[source_name] = read_reason
        failures.append(feature_unavailable_reason_failure(source_name, feature_probabilities, read_reason))
        return reasons, unavailable, tuple(failures)
    for key in keys:
        name = safe_str(key).strip()
        if not name.endswith("_unavailable_reason"):
            continue
        value = safe_mapping_get(feature_probabilities, key)
        if value is None:
            continue
        reason_key = name.removesuffix("_unavailable_reason").strip()
        reason = invalid_unavailable_reason_key_reason(reason_key)
        if reason == '':
            reason = invalid_unavailable_reason_value_reason(value)
        if reason != '':
            source_field = model_evidence_child_path(source_name, name) if source_name else name
            unavailable[source_field] = reason
            failures.append(feature_unavailable_reason_failure(source_field, value, reason))
            continue
        reasons[reason_key] = safe_str(value).strip()
    return reasons, unavailable, tuple(failures)

def secondary_unavailable_reasons(
    record: Mapping[str, object],
    *,
    primary_source_name: str,
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    """Return unavailable-reason evidence from non-primary model probability sources.

    Direct ``feature_probabilities`` is the primary source when present, but
    nested adaptive/profile/layered metadata can still carry output-affecting
    cold-start or degraded-state reasons.  Those reasons must not disappear
    merely because another probability source was chosen for scalar probability
    projection.
    """
    reasons: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for source_name, feature_probabilities in feature_probability_sources(record):
        if source_name == primary_source_name:
            continue
        source_reasons, source_unavailable, source_failures = unavailable_reasons(
            feature_probabilities,
            source_name=source_name,
        )
        for key, value in source_reasons.items():
            reasons[model_evidence_child_path(source_name, key)] = value
        unavailable.update(source_unavailable)
        failures.extend(source_failures)
    return reasons, unavailable, tuple(failures)

def unavailable_reason_key_text(key: object) -> tuple[str, str]:
    text, reason = safe_text_result(key)
    if reason:
        return model_evidence_type_marker(key), "unreadable_model_unavailable_reason_key"
    text = text.strip()
    if text == "":
        return "", "blank_model_unavailable_reason_key"
    return text, ""

def invalid_unavailable_reason_key_reason(key: object) -> str:
    _text, reason = unavailable_reason_key_text(key)
    return reason

def invalid_unavailable_reason_value_reason(value: object) -> str:
    if isinstance(value, str):
        text, reason = safe_text_result(value)
        if reason:
            return "unreadable_model_unavailable_reason"
        return "" if text.strip() != "" else "empty_model_unavailable_reason"
    return "non_text_model_unavailable_reason"

def sanitize_existing_unavailable_reasons_record(
    existing: object,
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    if existing is None or is_explicit_empty_text(existing):
        return {}, {}, ()
    if not model_evidence_is_mapping(existing):
        reason = "non_mapping_model_unavailable_reasons_record"
        return (
            {},
            {"model_evidence.unavailable_reasons": reason},
            (invalid_model_unavailable_reasons_record_failure(existing, reason),),
        )
    keys, read_reason = safe_mapping_keys(existing)
    if read_reason != '':
        return (
            {},
            {"model_evidence.unavailable_reasons": read_reason},
            (invalid_model_unavailable_reasons_record_failure(existing, read_reason),),
        )
    sanitized: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for raw_key in keys:
        key, key_reason = unavailable_reason_key_text(raw_key)
        value = safe_mapping_get(existing, raw_key)
        reason = key_reason
        if reason == '':
            reason = invalid_unavailable_reason_value_reason(value)
        if reason != '':
            source_field = model_evidence_child_path("model_evidence.unavailable_reasons", key) if key else "model_evidence.unavailable_reasons"
            unavailable[source_field] = reason
            failures.append(
                invalid_model_unavailable_reasons_record_failure(
                    value,
                    reason,
                    source_field=source_field,
                )
            )
            continue
        sanitized[key] = safe_str(value).strip()
    return sanitized, unavailable, tuple(failures)

def nested_model_signal_unavailable_reasons(
    record: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    """Project nested model-signal unavailable reasons into final JSON.

    Some model signal containers, especially profile coordinated validation, carry
    a canonical ``unavailable_reasons`` mapping alongside model-failure records.
    Failure records prove that a model degraded, but the unavailable-reasons map is
    the deterministic field-level evidence replay compares.  Publication must copy
    those already-computed reasons; it must not recompute the model signal or drop
    the field-level reasons when the signal is nested under adaptive metadata.
    """
    reasons: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    seen_paths: set[str] = set()

    def sanitize_reason_mapping(source_path: str, value: object) -> None:
        if source_path in seen_paths:
            return
        seen_paths.add(source_path)
        if value is None or is_explicit_empty_text(value):
            return
        if not model_evidence_is_mapping(value):
            reason = "non_mapping_model_unavailable_reasons_record"
            unavailable[model_evidence_child_path(source_path, "unavailable_reasons")] = reason
            failures.append(
                invalid_model_unavailable_reasons_record_failure(
                    value,
                    reason,
                    source_field=model_evidence_child_path(source_path, "unavailable_reasons"),
                )
            )
            return
        keys, read_reason = safe_mapping_keys(value)
        if read_reason != '':
            unavailable[model_evidence_child_path(source_path, "unavailable_reasons")] = read_reason
            failures.append(
                invalid_model_unavailable_reasons_record_failure(
                    value,
                    read_reason,
                    source_field=model_evidence_child_path(source_path, "unavailable_reasons"),
                )
            )
            return
        for raw_key in keys:
            key, key_reason = unavailable_reason_key_text(raw_key)
            item = safe_mapping_get(value, raw_key)
            reason = key_reason
            if reason == '':
                reason = invalid_unavailable_reason_value_reason(item)
            source_field = model_evidence_child_path(model_evidence_child_path(source_path, "unavailable_reasons"), key) if key else model_evidence_child_path(source_path, "unavailable_reasons")
            if reason != '':
                unavailable[source_field] = reason
                failures.append(
                    invalid_model_unavailable_reasons_record_failure(
                        item,
                        reason,
                        source_field=source_field,
                    )
                )
                continue
            reasons[model_evidence_child_path(source_path, key)] = safe_str(item).strip()

    def visit(source_path: str, value: object) -> None:
        if model_evidence_is_mapping(value):
            keys, read_reason = safe_mapping_keys(value)
            if read_reason != '':
                unavailable[source_path] = read_reason
                failures.append(invalid_model_unavailable_reasons_record_failure(value, read_reason, source_field=source_path))
                return
            if safe_mapping_contains(value, "unavailable_reasons"):
                sanitize_reason_mapping(source_path, safe_mapping_get(value, "unavailable_reasons"))
            for raw_key in keys:
                key = safe_str(raw_key)
                if key in {"unavailable_reasons", "feature_probabilities"} or key in MODEL_FAILURE_RECORD_KEYS:
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
    return reasons, unavailable, tuple(failures)

__all__ = ('feature_unavailable_reason_failure', 'invalid_unavailable_reason_key_reason', 'invalid_unavailable_reason_value_reason', 'nested_model_signal_unavailable_reasons', 'sanitize_existing_unavailable_reasons_record', 'secondary_unavailable_reasons', 'unavailable_reasons')
