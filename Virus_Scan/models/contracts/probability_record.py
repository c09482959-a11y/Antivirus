"""Immutable probability evidence records for model outputs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

import math

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.models.contracts.text_boundaries import (
    model_contract_field_reason,
    model_contract_metric_reason,
    model_contract_safe_text,
    model_contract_unavailable_reason_key,
    model_contract_unavailable_summary_reason,
)


@dataclass(frozen=True, slots=True)
class ProbabilityRecordErrors:
    ready: str = ""
    probability: str = ""
    support: str = ""
    count: str = ""
    vocab: str = ""
    smoothing: str = ""
    model_version: str = ""
    reason: str = ""
    source: str = ""
    target: str = ""
    flow: str = ""


@dataclass(frozen=True, slots=True)
class ProbabilityStateInputs:
    ready_value: bool
    probability_value: float | None
    probability_error: str
    metric_errors: tuple[str, ...]
    text_errors: tuple[str, ...]
    provenance_errors: tuple[str, ...]
    ready_error: str = ""
    reason_value: str | None = None
    record_ready: bool = False


def _safe_mapping_key_text(value: object) -> str | None:
    if isinstance(value, str):
        return str.__str__(value)
    return None


def _first_nonempty_text(*values: object, default: str = "") -> str:
    for value in values:
        if value is None:
            continue
        text = str.strip(model_contract_safe_text(value))
        if text != "":
            return text
    return str.strip(model_contract_safe_text(default)) if default is not None else ""

def _safe_iterable(value: object, *, reason: str) -> tuple[tuple[object, ...], str]:
    if value is None:
        return (), ""
    if type(value) in (tuple, list):
        return tuple(value), ""
    if type(value) in (set, frozenset):
        return tuple(sorted(value, key=model_contract_safe_text)), ""
    return (), reason


def _safe_mapping_get(record: Mapping[str, object], key: str, default: object = None) -> tuple[bool, object]:
    items = no_hook_mapping_items(record, allow_dict_subclass=True)
    if items is None:
        return False, default
    for raw_key, raw_value in items:
        key_text = _safe_mapping_key_text(raw_key)
        if key_text is not None and key_text == key:
            return True, raw_value
    return True, default


def _safe_mapping_contains(record: Mapping[str, object], key: str) -> bool:
    items = no_hook_mapping_items(record, allow_dict_subclass=True)
    if items is None:
        return False
    for raw_key, _raw_value in items:
        key_text = _safe_mapping_key_text(raw_key)
        if key_text is not None and key_text == key:
            return True
    return False


def _probability_value(probability: object) -> tuple[float | None, str]:
    if probability is None:
        return None, ""
    if type(probability) is bool:
        return None, "non_numeric_probability"
    if type(probability) is int:
        value = float(probability)
    elif type(probability) is float:
        value = probability
    elif isinstance(probability, str):
        try:
            value = float(str.__str__(probability).strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return None, "non_numeric_probability"
    elif type(probability) in (bytes, bytearray):
        try:
            value = float(bytes(probability).decode("utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return None, "non_numeric_probability"
    else:
        return None, "non_numeric_probability"
    if not math.isfinite(value):
        return None, "non_finite_probability"
    if value < 0.0 or value > 1.0:
        return None, "out_of_bounds_probability"
    return value, ""


def _nonnegative_count_value(value: object, *, field_name: str) -> tuple[int | None, str]:
    if value is None:
        return 0, ""
    if isinstance(value, str) and str.strip(str.__str__(value)) == "":
        return 0, ""
    if type(value) is bool:
        return None, model_contract_metric_reason("non_numeric", field_name)
    if type(value) is int:
        metric = float(value)
    elif type(value) is float:
        metric = value
    elif isinstance(value, str):
        try:
            metric = float(str.__str__(value).strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return None, model_contract_metric_reason("non_numeric", field_name)
    elif type(value) in (bytes, bytearray):
        try:
            metric = float(bytes(value).decode("utf-8", "replace").strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return None, model_contract_metric_reason("non_numeric", field_name)
    else:
        return None, model_contract_metric_reason("non_numeric", field_name)
    if not math.isfinite(metric):
        return None, model_contract_metric_reason("non_finite", field_name)
    if metric < 0.0:
        return None, model_contract_metric_reason("negative", field_name)
    if not metric.is_integer():
        return None, model_contract_metric_reason("non_integer", field_name)
    return int(metric), ""


def _materialized_count_value(value: object) -> int | None:
    metric, reason = _nonnegative_count_value(value, field_name="count_support")
    if reason:
        return None
    return metric


def _readiness_value(value: object) -> tuple[bool, str]:
    if isinstance(value, bool):
        return value, ""
    if value is None:
        return False, ""
    return False, "non_boolean_ready_flag"


def _nonempty_text_value(value: object, *, default: str, field_name: str) -> tuple[str, str]:
    if value is None:
        return default, model_contract_field_reason("missing", field_name)
    if not isinstance(value, str):
        return default, model_contract_field_reason("non_text", field_name)
    text = str.strip(model_contract_safe_text(value))
    if text == "":
        return default, model_contract_field_reason("blank", field_name)
    return text, ""


def _optional_reason_value(value: object) -> tuple[str | None, str]:
    if value is None:
        return None, ""
    if not isinstance(value, str):
        return None, "non_text_reason"
    text = str.strip(model_contract_safe_text(value))
    if text == "":
        return None, ""
    return text, ""


def _optional_identity_text_value(value: object, *, field_name: str) -> tuple[str | None, str]:
    if value is None:
        return None, ""
    if not isinstance(value, str):
        return None, model_contract_field_reason("non_text", field_name)
    text = str.strip(model_contract_safe_text(value))
    if text == "":
        return None, model_contract_field_reason("blank", field_name)
    return text, ""


def _flow_value(value: object) -> tuple[tuple[str, ...], str]:
    if value is None:
        return (), ""
    if isinstance(value, str) or type(value) in (bytes, bytearray) or isinstance(value, Mapping):
        return (), "non_sequence_flow"
    items, read_error = _safe_iterable(value, reason="unreadable_flow")
    if read_error:
        return (), read_error
    normalized: list[str] = []
    for item in items:
        if not isinstance(item, str):
            return (), "non_text_flow_item"
        text = str.strip(model_contract_safe_text(item))
        if text == "":
            return (), "blank_flow_item"
        normalized.append(text)
    return tuple(normalized), ""


def _unavailable_reason_value(value: object) -> tuple[str, str]:
    if isinstance(value, str):
        reason = str.strip(model_contract_safe_text(value))
        if reason != "":
            return reason, ""
        return "invalid_unavailable_reason", "blank_unavailable_reason"
    return "invalid_unavailable_reason", "non_text_unavailable_reason"


def _safe_mapping_keys(record: Mapping[str, object]) -> tuple[tuple[str, ...], str]:
    items = no_hook_mapping_items(record, allow_dict_subclass=True)
    if items is None:
        return (), "unreadable_probability_record"
    keys = tuple(key_text for key_text in (_safe_mapping_key_text(key) for key, _value in items) if key_text is not None)
    return tuple(sorted(keys, key=model_contract_safe_text)), ""


def _copy_unavailable_reasons(record: Mapping[str, object], materialized: dict[str, object]) -> None:
    keys, read_error = _safe_mapping_keys(record)
    if read_error:
        _set_unavailable_reason(materialized, "probability", read_error)
        materialized["reason"] = _first_nonempty_text(materialized.get("reason"), read_error)
        return
    for name in keys:
        if not name.endswith("_unavailable_reason"):
            continue
        ok, raw_reason = _safe_mapping_get(record, name)
        if not ok:
            reason = "invalid_unavailable_reason"
            reason_error = "unreadable_unavailable_reason"
        else:
            reason, reason_error = _unavailable_reason_value(raw_reason)
        materialized[name] = reason
        if name != "probability_unavailable_reason":
            _set_unavailable_reason(
                materialized,
                "probability",
                _first_nonempty_text(reason_error, reason, model_contract_unavailable_summary_reason(name)),
            )
        if reason_error:
            target = name.removesuffix("_unavailable_reason")
            materialized["reason"] = _first_nonempty_text(materialized.get("reason"), reason_error, target)


def _set_unavailable_reason(materialized: dict[str, object], field_name: str, reason: str) -> None:
    reason = _first_nonempty_text(reason)
    existing_reason = _first_nonempty_text(materialized.get(model_contract_unavailable_reason_key(field_name)))
    if reason != "" and existing_reason == "":
        materialized[model_contract_unavailable_reason_key(field_name)] = reason



def _probability_record_error_groups(errors: ProbabilityRecordErrors) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    metric_errors = tuple(error for error in (errors.support, errors.count, errors.vocab) if error)
    text_errors = tuple(error for error in (errors.smoothing, errors.model_version, errors.reason) if error)
    provenance_errors = tuple(error for error in (errors.source, errors.target, errors.flow) if error)
    return metric_errors, text_errors, provenance_errors


def _apply_probability_record_field_errors(record: dict[str, object], errors: ProbabilityRecordErrors) -> None:
    for field_name, error in (
        ("ready", errors.ready),
        ("support", errors.support),
        ("count", errors.count),
        ("vocab", errors.vocab),
        ("smoothing", errors.smoothing),
        ("model_version", errors.model_version),
        ("reason", errors.reason),
        ("source", errors.source),
        ("target", errors.target),
        ("flow", errors.flow),
    ):
        if error:
            record[model_contract_unavailable_reason_key(field_name)] = error


def _apply_probability_record_probability_error(record: dict[str, object], state: ProbabilityStateInputs) -> None:
    if state.probability_error:
        record["probability_unavailable_reason"] = state.probability_error
        record["reason"] = _first_nonempty_text(state.reason_value, state.probability_error)
    elif state.ready_error and state.probability_value is not None:
        record["probability_unavailable_reason"] = "not_ready_probability_present"
        record["reason"] = _first_nonempty_text(state.reason_value, "not_ready_probability_present")
    elif state.metric_errors:
        record["probability_unavailable_reason"] = state.metric_errors[0]
        record["reason"] = _first_nonempty_text(state.reason_value, state.metric_errors[0])
    elif state.text_errors:
        record["probability_unavailable_reason"] = state.text_errors[0]
        record["reason"] = _first_nonempty_text(state.reason_value, state.text_errors[0])
    elif state.provenance_errors:
        record["probability_unavailable_reason"] = state.provenance_errors[0]
        record["reason"] = _first_nonempty_text(state.reason_value, state.provenance_errors[0])
    elif state.ready_value and state.probability_value is None:
        record["probability_unavailable_reason"] = "ready_probability_missing"
        record["reason"] = _first_nonempty_text(state.reason_value, "ready_probability_missing")
    elif not state.ready_value and state.probability_value is not None:
        record["probability_unavailable_reason"] = "not_ready_probability_present"
        record["reason"] = _first_nonempty_text(state.reason_value, "not_ready_probability_present")
    if _first_nonempty_text(record.get("reason")) == "" and not state.record_ready:
        record["reason"] = _first_nonempty_text(record.get("probability_unavailable_reason"), "not_ready")


def _non_mapping_probability_materialization(value: object) -> dict[str, object]:
    return {
        "ready": False,
        "probability": None,
        "support": None,
        "count": None,
        "vocab": None,
        "smoothing": "none",
        "reason": "non_mapping_probability_record",
        "model_version": "probability_record_v1",
        "probability_unavailable_reason": "non_mapping_probability_record",
        "value_type": no_hook_type_name(value),
    }


def _probability_record_missing_required(record: Mapping[str, object]) -> set[str]:
    return {
        field
        for field in (
            "ready",
            "probability",
            "support",
            "count",
            "vocab",
            "smoothing",
            "reason",
            "model_version",
        )
        if not _safe_mapping_contains(record, field)
    }


def _apply_materialized_missing_required(missing_required: set[str], errors: dict[str, str]) -> None:
    for field in missing_required:
        errors[field] = "missing_probability_record_field"


def _apply_unreadable_probability_record(errors: dict[str, str]) -> None:
    for field in ("ready", "probability", "support", "count", "vocab", "smoothing", "model_version", "reason"):
        errors[field] = "unreadable_probability_record"


def _apply_materialized_field_errors(materialized: dict[str, object], errors: dict[str, str]) -> None:
    for field in ("ready", "support", "count", "vocab", "smoothing", "model_version", "reason", "source", "target", "flow"):
        if errors.get(field):
            _set_unavailable_reason(materialized, field, errors[field])


def _apply_materialized_probability_state(materialized: dict[str, object], state: ProbabilityStateInputs) -> None:
    if state.probability_error:
        _set_unavailable_reason(materialized, "probability", state.probability_error)
    elif state.ready_value and state.probability_value is None:
        _set_unavailable_reason(materialized, "probability", "ready_probability_missing")
    elif not state.ready_value and state.probability_value is not None:
        _set_unavailable_reason(materialized, "probability", "not_ready_probability_present")
    elif materialized["ready"] and _first_nonempty_text(materialized.get("probability_unavailable_reason")) == "":
        materialized["probability"] = state.probability_value
    for error_group in (state.metric_errors, state.text_errors, state.provenance_errors):
        if error_group and _first_nonempty_text(materialized.get("probability_unavailable_reason")) == "":
            _set_unavailable_reason(materialized, "probability", error_group[0])
    if not materialized["ready"] and _first_nonempty_text(materialized.get("reason")) == "":
        materialized["reason"] = _first_nonempty_text(
            materialized.get("probability_unavailable_reason"),
            materialized.get("ready_unavailable_reason"),
            "not_ready",
        )

def make_probability_record(
    *,
    ready: object,
    probability: object,
    support: object,
    count: object,
    vocab: object,
    smoothing: object,
    reason: object,
    source: object = None,
    target: object = None,
    flow: Iterable[object] | None = None,
    model_version: str = "probability_record_v1",
) -> Mapping[str, object]:
    """Return an immutable, deterministic probability evidence mapping."""
    ready_value, ready_error = _readiness_value(ready)
    probability_value, probability_error = _probability_value(probability)
    support_value, support_error = _nonnegative_count_value(support, field_name="support")
    count_value, count_error = _nonnegative_count_value(count, field_name="count")
    vocab_value, vocab_error = _nonnegative_count_value(vocab, field_name="vocab")
    smoothing_value, smoothing_error = _nonempty_text_value(smoothing, default="none", field_name="smoothing")
    model_version_value, model_version_error = _nonempty_text_value(
        model_version, default="probability_record_v1", field_name="model_version"
    )
    reason_value, reason_error = _optional_reason_value(reason)
    source_value, source_error = _optional_identity_text_value(source, field_name="source")
    target_value, target_error = _optional_identity_text_value(target, field_name="target")
    flow_value, flow_error = _flow_value(flow)
    field_errors = ProbabilityRecordErrors(
        ready=ready_error, probability=probability_error, support=support_error,
        count=count_error, vocab=vocab_error, smoothing=smoothing_error,
        model_version=model_version_error, reason=reason_error, source=source_error,
        target=target_error, flow=flow_error,
    )
    metric_errors, text_errors, provenance_errors = _probability_record_error_groups(field_errors)
    record_ready = (
        ready_value and not ready_error and not probability_error and not metric_errors
        and not text_errors and not provenance_errors and probability_value is not None
    )
    record: dict[str, object] = {
        "ready": record_ready,
        "probability": probability_value if record_ready else None,
        "support": support_value,
        "count": count_value,
        "vocab": vocab_value,
        "smoothing": smoothing_value,
        "reason": reason_value,
        "source": source_value,
        "target": target_value,
        "flow": flow_value,
        "model_version": model_version_value,
    }
    _apply_probability_record_field_errors(record, field_errors)
    _apply_probability_record_probability_error(
        record,
        ProbabilityStateInputs(
            ready_value=ready_value,
            ready_error=ready_error,
            probability_value=probability_value,
            probability_error=probability_error,
            metric_errors=metric_errors,
            text_errors=text_errors,
            provenance_errors=provenance_errors,
            reason_value=reason_value,
            record_ready=record_ready,
        ),
    )
    return MappingProxyType(record)




def _materialize_markov_probability_metadata(
    record: Mapping[str, object], materialized: dict[str, object]
) -> None:
    """Preserve validated Markov posterior provenance during JSON materialization."""
    markov_fields = (
        "posterior_predictive_probability", "vocabulary_size", "alpha",
        "unseen_bucket_policy", "unseen_bucket_count", "minimum_support",
        "fallback_level", "fallback_confidence", "context_support",
        "state_schema", "context_key", "previous_stage",
    )
    if not any(_safe_mapping_contains(record, field) for field in markov_fields):
        return

    count_fields = (
        "vocabulary_size", "unseen_bucket_count", "minimum_support",
        "context_support", "state_schema",
    )
    for field in count_fields:
        value, error = _nonnegative_count_value(
            _safe_mapping_get(record, field, 0)[1], field_name=field,
        )
        materialized[field] = value
        if error:
            _set_unavailable_reason(materialized, field, error)

    for field, default in (
        ("unseen_bucket_policy", "explicit_single_unseen_target"),
        ("fallback_level", "global"),
    ):
        value, error = _nonempty_text_value(
            _safe_mapping_get(record, field, default)[1],
            default=default, field_name=field,
        )
        materialized[field] = value
        if error:
            _set_unavailable_reason(materialized, field, error)

    for field in ("context_key", "previous_stage"):
        value, error = _optional_identity_text_value(
            _safe_mapping_get(record, field)[1], field_name=field,
        )
        materialized[field] = value
        if error:
            _set_unavailable_reason(materialized, field, error)

    alpha_raw = _safe_mapping_get(record, "alpha")[1]
    alpha_value = (
        float(alpha_raw)
        if type(alpha_raw) in (int, float) and not isinstance(alpha_raw, bool)
        else None
    )
    if alpha_value is None or not math.isfinite(alpha_value) or alpha_value <= 0.0:
        materialized["alpha"] = None
        _set_unavailable_reason(materialized, "alpha", "invalid_markov_smoothing_alpha")
    else:
        materialized["alpha"] = alpha_value

    confidence, confidence_error = _probability_value(
        _safe_mapping_get(record, "fallback_confidence", 0.0)[1]
    )
    materialized["fallback_confidence"] = confidence
    if confidence_error:
        _set_unavailable_reason(materialized, "fallback_confidence", confidence_error)

    posterior, posterior_error = _probability_value(
        _safe_mapping_get(record, "posterior_predictive_probability")[1]
    )
    materialized["posterior_predictive_probability"] = posterior
    if posterior_error:
        _set_unavailable_reason(
            materialized, "posterior_predictive_probability", posterior_error
        )
    elif posterior != materialized.get("probability"):
        _set_unavailable_reason(
            materialized,
            "posterior_predictive_probability",
            "markov_posterior_probability_mismatch",
        )

    for field in markov_fields:
        reason_key = model_contract_unavailable_reason_key(field)
        present, value = _safe_mapping_get(record, reason_key)
        if present and type(value) is str and value != "":
            materialized[reason_key] = value

    if any(
        type(materialized.get(model_contract_unavailable_reason_key(field))) is str
        and materialized.get(model_contract_unavailable_reason_key(field)) != ""
        for field in markov_fields
    ):
        materialized["ready"] = False
        materialized["probability"] = None
        materialized["posterior_predictive_probability"] = None
        materialized["reason"] = _first_nonempty_text(
            materialized.get("reason"), "invalid_markov_probability_metadata"
        )

def materialize_probability_record(record: Mapping[str, object]) -> dict[str, object]:
    """Materialize a probability record for deterministic JSON output."""
    if not isinstance(record, Mapping):
        return _non_mapping_probability_materialization(record)
    missing_required = _probability_record_missing_required(record)
    record_unreadable = not any(
        _safe_mapping_contains(record, field)
        for field in ("ready", "probability", "support", "count", "vocab", "smoothing", "reason", "model_version")
    )
    ready_value, ready_error = _readiness_value(_safe_mapping_get(record, "ready", False)[1])
    probability_value, probability_error = _probability_value(_safe_mapping_get(record, "probability")[1])
    support_value, support_error = _nonnegative_count_value(_safe_mapping_get(record, "support", 0)[1], field_name="support")
    count_value, count_error = _nonnegative_count_value(_safe_mapping_get(record, "count", 0)[1], field_name="count")
    vocab_value, vocab_error = _nonnegative_count_value(_safe_mapping_get(record, "vocab", 0)[1], field_name="vocab")
    smoothing_value, smoothing_error = _nonempty_text_value(
        _safe_mapping_get(record, "smoothing", "none")[1], default="none", field_name="smoothing"
    )
    model_version_value, model_version_error = _nonempty_text_value(
        _safe_mapping_get(record, "model_version", "probability_record_v1")[1],
        default="probability_record_v1", field_name="model_version"
    )
    reason_value, reason_error = _optional_reason_value(_safe_mapping_get(record, "reason")[1])
    if record_unreadable:
        if probability_error == "":
            probability_error = "unreadable_probability_record"
        reason_value = _first_nonempty_text(reason_value, "unreadable_probability_record")
    errors = {
        "ready": ready_error, "probability": probability_error, "support": support_error,
        "count": count_error, "vocab": vocab_error, "smoothing": smoothing_error,
        "model_version": model_version_error, "reason": reason_error,
    }
    _apply_materialized_missing_required(missing_required, errors)
    if record_unreadable:
        _apply_unreadable_probability_record(errors)
        reason_value = "unreadable_probability_record"
    source_value, source_error = _optional_identity_text_value(_safe_mapping_get(record, "source")[1], field_name="source")
    target_value, target_error = _optional_identity_text_value(_safe_mapping_get(record, "target")[1], field_name="target")
    flow_value, flow_error = _flow_value(_safe_mapping_get(record, "flow", ())[1])
    errors.update({"source": source_error, "target": target_error, "flow": flow_error})
    field_errors = ProbabilityRecordErrors(
        ready=errors["ready"], probability=errors["probability"], support=errors["support"],
        count=errors["count"], vocab=errors["vocab"], smoothing=errors["smoothing"],
        model_version=errors["model_version"], reason=errors["reason"], source=source_error,
        target=target_error, flow=flow_error,
    )
    metric_errors, text_errors, provenance_errors = _probability_record_error_groups(field_errors)
    materialized: dict[str, object] = {
        "ready": ready_value and not errors["ready"] and not errors["probability"]
        and not metric_errors and not text_errors and not provenance_errors and probability_value is not None,
        "probability": None,
        "support": support_value,
        "count": count_value,
        "vocab": vocab_value,
        "smoothing": smoothing_value,
        "reason": reason_value,
        "source": source_value,
        "target": target_value,
        "flow": flow_value,
        "model_version": model_version_value,
    }
    if not record_unreadable:
        _copy_unavailable_reasons(record, materialized)
    if _first_nonempty_text(materialized.get("probability_unavailable_reason")) != "":
        materialized["ready"] = False
    _apply_materialized_field_errors(materialized, errors)
    _apply_materialized_probability_state(
        materialized,
        ProbabilityStateInputs(
            ready_value=ready_value,
            probability_value=probability_value,
            probability_error=errors["probability"],
            metric_errors=metric_errors,
            text_errors=text_errors,
            provenance_errors=provenance_errors,
        ),
    )
    _materialize_markov_probability_metadata(record, materialized)
    return materialized



def make_markov_probability_record(
    *,
    ready: object,
    probability: object,
    support: object,
    count: object,
    vocab: object,
    smoothing: object,
    reason: object,
    source: object = None,
    target: object = None,
    flow: Iterable[object] | None = None,
    model_version: str = "markov_probability_v1",
    alpha: object = 0.5,
    unseen_bucket_policy: object = "explicit_single_unseen_target",
    unseen_bucket_count: object = 1,
    minimum_support: object = 0,
    fallback_level: object = "global",
    fallback_confidence: object = 0.0,
    context_support: object = 0,
    state_schema: object = 0,
    context_key: object = None,
    previous_stage: object = None,
) -> Mapping[str, object]:
    """Return the canonical immutable Markov probability contract record."""
    base = make_probability_record(
        ready=ready,
        probability=probability,
        support=support,
        count=count,
        vocab=vocab,
        smoothing=smoothing,
        reason=reason,
        source=source,
        target=target,
        flow=flow,
        model_version=model_version,
    )
    record = dict(base)
    alpha_value = float(alpha) if type(alpha) in (int, float) and not isinstance(alpha, bool) else None
    if alpha_value is None or not math.isfinite(alpha_value) or alpha_value <= 0.0:
        record["alpha"] = None
        record["alpha_unavailable_reason"] = "invalid_markov_smoothing_alpha"
        record["ready"] = False
        record["probability"] = None
        record["probability_unavailable_reason"] = "invalid_markov_smoothing_alpha"
        record["reason"] = _first_nonempty_text(record.get("reason"), "invalid_markov_smoothing_alpha")
    else:
        record["alpha"] = alpha_value
    bucket_value, bucket_error = _nonnegative_count_value(
        unseen_bucket_count, field_name="unseen_bucket_count",
    )
    minimum_value, minimum_error = _nonnegative_count_value(
        minimum_support, field_name="minimum_support",
    )
    context_support_value, context_support_error = _nonnegative_count_value(
        context_support, field_name="context_support",
    )
    state_schema_value, state_schema_error = _nonnegative_count_value(
        state_schema, field_name="state_schema",
    )
    policy_value, policy_error = _nonempty_text_value(
        unseen_bucket_policy,
        default="explicit_single_unseen_target",
        field_name="unseen_bucket_policy",
    )
    fallback_value, fallback_error = _nonempty_text_value(
        fallback_level,
        default="global",
        field_name="fallback_level",
    )
    confidence_value, confidence_error = _probability_value(fallback_confidence)
    context_key_value, context_key_error = _optional_identity_text_value(
        context_key, field_name="context_key",
    )
    previous_stage_value, previous_stage_error = _optional_identity_text_value(
        previous_stage, field_name="previous_stage",
    )
    record.update(
        {
            "posterior_predictive_probability": record.get("probability"),
            "vocabulary_size": record.get("vocab"),
            "unseen_bucket_policy": policy_value,
            "unseen_bucket_count": bucket_value,
            "minimum_support": minimum_value,
            "fallback_level": fallback_value,
            "fallback_confidence": confidence_value,
            "context_support": context_support_value,
            "state_schema": state_schema_value,
            "context_key": context_key_value,
            "previous_stage": previous_stage_value,
        }
    )
    for field_name, error in (
        ("unseen_bucket_policy", policy_error),
        ("unseen_bucket_count", bucket_error),
        ("minimum_support", minimum_error),
        ("fallback_level", fallback_error),
        ("fallback_confidence", confidence_error),
        ("context_support", context_support_error),
        ("state_schema", state_schema_error),
        ("context_key", context_key_error),
        ("previous_stage", previous_stage_error),
    ):
        if error:
            record[model_contract_unavailable_reason_key(field_name)] = error
            record["ready"] = False
            record["probability"] = None
            record["posterior_predictive_probability"] = None
            record["probability_unavailable_reason"] = error
            record["reason"] = _first_nonempty_text(record.get("reason"), error)
    return MappingProxyType(record)


__all__ = (
    "make_markov_probability_record",
    "make_probability_record",
    "materialize_probability_record",
)
