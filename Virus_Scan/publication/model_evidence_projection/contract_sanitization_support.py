"""Support helpers for model-evidence contract sanitization."""

from __future__ import annotations

from typing import NamedTuple

from .constants import MODEL_PROBABILITY_RECORD_REQUIRED_TEXT_FIELDS
from .probability_validation import (
    contract_unavailable_reason_target,
    invalid_contract_count_metric_failure,
    invalid_contract_metric_failure,
    invalid_contract_readiness_flag_failure,
    invalid_contract_schema_failure,
    is_contract_boolean_flag_field,
    is_contract_nonnegative_integer_field,
    is_contract_probability_mapping_field,
    is_contract_scalar_probability_field,
    is_contract_unavailable_reason_field,
    is_probability_record_container,
    valid_boolean_flag,
    valid_nonnegative_integer_metric,
    valid_probability,
    valid_probability_flow,
    valid_probability_identity_text,
    valid_probability_record_text,
)
from .record_validation import is_replay_comparison_record_container, valid_replay_mismatch_fields
from .safe_mapping import (
    model_evidence_child_path,
    model_evidence_unavailable_field,
    model_evidence_unavailable_reasons_field,
    safe_mapping_keys,
    safe_mapping_read,
    safe_str,
    model_evidence_is_mapping,
)


class ContractItemSanitization(NamedTuple):
    """Sanitized representation for one contract field."""

    handled: bool
    values: dict[str, object]
    unavailable: dict[str, object]
    failures: tuple[dict[str, object], ...]


def _handled(
    values: dict[str, object],
    unavailable: dict[str, object] | None = None,
    failures: tuple[dict[str, object], ...] = (),
) -> ContractItemSanitization:
    return ContractItemSanitization(True, values, unavailable or {}, failures)


def _unhandled() -> ContractItemSanitization:
    return ContractItemSanitization(False, {}, {}, ())


def _sanitize_unavailable_reason(
    source_container: str,
    key: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    target_path = contract_unavailable_reason_target(metric_path)
    item_text = safe_str(item).strip() if isinstance(item, str) else ""
    if isinstance(item, str) and item_text != "":
        reason = item_text
        return _handled({key: reason}, {model_evidence_child_path(source_container, target_path): reason})
    reason = "invalid_model_unavailable_reason"
    return _handled(
        {key: reason},
        {model_evidence_child_path(source_container, target_path): reason},
        (invalid_contract_schema_failure(source_container, metric_path, reason),),
    )


def _sanitize_probability_text(
    source_container: str,
    key: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    valid_text, reason = valid_probability_record_text(item)
    if valid_text:
        return _handled({key: safe_str(item).strip()})
    reason_key = "reason_unavailable_reason" if key == "reason" else model_evidence_unavailable_field(key)
    return _handled(
        {reason_key: reason},
        {model_evidence_child_path(source_container, metric_path): reason},
        (invalid_contract_schema_failure(source_container, metric_path, reason),),
    )


def _sanitize_probability_identity(
    source_container: str,
    key: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    valid_text, reason = valid_probability_identity_text(item)
    if valid_text:
        return _handled({key: safe_str(item).strip()})
    return _handled(
        {model_evidence_unavailable_field(key): reason},
        {model_evidence_child_path(source_container, metric_path): reason},
        (invalid_contract_schema_failure(source_container, metric_path, reason),),
    )


def _sanitize_probability_flow(
    source_container: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    flow, reason = valid_probability_flow(item)
    if reason == "":
        return _handled({"flow": flow})
    return _handled(
        {"flow_unavailable_reason": reason},
        {model_evidence_child_path(source_container, metric_path): reason},
        (invalid_contract_schema_failure(source_container, metric_path, reason),),
    )


def _sanitize_replay_mismatch_fields(
    source_container: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    fields, reason = valid_replay_mismatch_fields(item)
    if reason == "":
        return _handled({"mismatch_fields": fields})
    return _handled(
        {"mismatch_fields_unavailable_reason": reason},
        {model_evidence_child_path(source_container, metric_path): reason},
        (invalid_contract_schema_failure(source_container, metric_path, reason),),
    )


def _sanitize_scalar_probability(
    source_container: str,
    key: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    valid, probability, reason = valid_probability(item)
    if valid:
        return _handled({key: probability})
    return _handled(
        {model_evidence_unavailable_field(key): reason},
        {model_evidence_child_path(source_container, metric_path): reason},
        (invalid_contract_metric_failure(source_container, metric_path, item, reason),),
    )


def _sanitize_boolean_flag(
    source_container: str,
    key: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    boolean_reason_field = "matched" if key == "matched" else "readiness"
    valid, flag, reason = valid_boolean_flag(item, field_name=boolean_reason_field)
    if valid:
        return _handled({key: flag})
    return _handled(
        {model_evidence_unavailable_field(key): reason},
        {model_evidence_child_path(source_container, metric_path): reason},
        (invalid_contract_readiness_flag_failure(source_container, metric_path, item, reason),),
    )


def _sanitize_integer_metric(
    source_container: str,
    key: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    valid, metric, reason = valid_nonnegative_integer_metric(item)
    if valid:
        return _handled({key: metric})
    return _handled(
        {model_evidence_unavailable_field(key): reason},
        {model_evidence_child_path(source_container, metric_path): reason},
        (invalid_contract_count_metric_failure(source_container, metric_path, item, reason),),
    )


def _sanitize_probability_mapping(
    source_container: str,
    key: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    if item is None:
        return _handled({})
    if not model_evidence_is_mapping(item):
        reason = "non_mapping_probability_container"
        return _handled(
            {model_evidence_unavailable_field(key): reason},
            {model_evidence_child_path(source_container, metric_path): reason},
            (invalid_contract_metric_failure(source_container, metric_path, item, reason),),
        )
    probability_keys, probability_key_reason = safe_mapping_keys(item)
    if probability_key_reason:
        return _handled(
            {model_evidence_unavailable_field(key): probability_key_reason},
            {model_evidence_child_path(source_container, metric_path): probability_key_reason},
            (invalid_contract_schema_failure(source_container, metric_path, probability_key_reason),),
        )
    probability_map: dict[str, object] = {}
    probability_unavailable: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for raw_probability_key in probability_keys:
        probability_key = safe_str(raw_probability_key)
        probability_path = model_evidence_child_path(metric_path, probability_key)
        probability_readable, probability_value = safe_mapping_read(item, raw_probability_key)
        if not probability_readable:
            reason = "unreadable_probability_mapping_item"
            probability_unavailable[probability_key] = reason
            unavailable[model_evidence_child_path(source_container, probability_path)] = reason
            failures.append(invalid_contract_schema_failure(source_container, probability_path, reason))
            continue
        if probability_value is None:
            continue
        valid, probability, reason = valid_probability(probability_value)
        if valid:
            probability_map[probability_key] = probability
        else:
            probability_unavailable[probability_key] = reason
            unavailable[model_evidence_child_path(source_container, probability_path)] = reason
            failures.append(
                invalid_contract_metric_failure(source_container, probability_path, probability_value, reason)
            )
    values: dict[str, object] = {}
    if probability_map:
        values[key] = probability_map
    if probability_unavailable:
        values[model_evidence_unavailable_reasons_field(key)] = probability_unavailable
    return _handled(values, unavailable, tuple(failures))


def sanitize_contract_field(
    source_container: str,
    key: str,
    item: object,
    metric_path: str,
) -> ContractItemSanitization:
    """Sanitize one contract-specific field if it has a declared contract."""

    if is_contract_unavailable_reason_field(key):
        return _sanitize_unavailable_reason(source_container, key, item, metric_path)
    if is_probability_record_container(source_container) and item is not None:
        if key in MODEL_PROBABILITY_RECORD_REQUIRED_TEXT_FIELDS or key == "reason":
            return _sanitize_probability_text(source_container, key, item, metric_path)
        if key in {"source", "target"}:
            return _sanitize_probability_identity(source_container, key, item, metric_path)
        if key == "flow":
            return _sanitize_probability_flow(source_container, item, metric_path)
    if is_replay_comparison_record_container(source_container) and key == "mismatch_fields":
        return _sanitize_replay_mismatch_fields(source_container, item, metric_path)
    if is_contract_scalar_probability_field(key) and item is not None:
        return _sanitize_scalar_probability(source_container, key, item, metric_path)
    if is_contract_boolean_flag_field(key) and item is not None:
        return _sanitize_boolean_flag(source_container, key, item, metric_path)
    if is_contract_nonnegative_integer_field(key) and item is not None:
        return _sanitize_integer_metric(source_container, key, item, metric_path)
    if is_contract_probability_mapping_field(key):
        return _sanitize_probability_mapping(source_container, key, item, metric_path)
    return _unhandled()


__all__ = ("ContractItemSanitization", "sanitize_contract_field")
