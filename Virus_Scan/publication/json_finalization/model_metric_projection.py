"""Model probability projection helpers for final JSON."""
from __future__ import annotations

import math

from Virus_Scan.contracts.no_hook_materialization import exact_finite_float_or_none
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_items,
    projection_failure,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    json_key_result,
    mapping_pair_sort_key,
    projection_text_result,
    unavailable_reason_field,
)


PLR2004N4 = 4

ModelMetricValue = object
ModelMetricRecord = dict[str, ModelMetricValue]


def is_model_probability_metric_key(key: ModelMetricValue) -> bool:
    text, reason = projection_text_result(key)
    name = "" if reason else text.strip().lower()
    if name in {"probability", "stage_probability", "sequence_probability", "confidence"}:
        return True
    if name.endswith("_confidence") and not name.endswith("_confidence_amplifier"):
        return True
    if not name.endswith("_probability"):
        return False
    return name not in {
        "probability_ready",
        "probability_support",
        "probability_count",
        "probability_unavailable_reason",
    }


def is_model_probability_mapping_key(key: ModelMetricValue) -> bool:
    text, reason = projection_text_result(key)
    name = "" if reason else text.strip().lower()
    return name in {"pair_probabilities", "feature_probabilities", "probabilities"} or name.endswith("_probabilities")


def model_metric_projection_failure(reason: str) -> ModelMetricRecord:
    return {"model_signal_projection_failed": True, "reason": reason}


_MODEL_FAILURE_KEYS = frozenset(("model_failure", "model_failure_record", "model_failures"))


def _bounded_probability_side_evidence(value: ModelMetricValue, *, depth: int = 0) -> ModelMetricValue:
    if depth > PLR2004N4:
        return model_metric_projection_failure("probability_side_evidence_depth_limit_exceeded")
    items = final_json_mapping_items(value)
    if items is not None:
        out: ModelMetricRecord = {}
        for index, (key, item) in enumerate(sorted(items, key=mapping_pair_sort_key)[:16]):
            out_key, key_reason = json_key_result(key, index)
            if key_reason:
                out[out_key] = projection_failure(key_reason, key)
            else:
                out[out_key] = _bounded_probability_side_evidence(item, depth=depth + 1)
        return out
    if type(value) is tuple:
        return [_bounded_probability_side_evidence(item, depth=depth + 1) for item in value[:16]]
    if type(value) is list:
        return [_bounded_probability_side_evidence(item, depth=depth + 1) for item in value[:16]]
    if isinstance(value, str) or type(value) in (int, float, bool) or value is None:
        if type(value) is float and not math.isfinite(value):
            return model_metric_projection_failure("non_finite_probability_side_evidence")
        return str.__str__(value)[:512] if isinstance(value, str) else value
    return model_metric_projection_failure("non_materializable_probability_side_evidence")


def bounded_probability_mapping(value: ModelMetricValue, limit: int = 12) -> ModelMetricRecord:
    items = final_json_mapping_items(value)
    if items is None:
        return {
            "_unavailable_mapping": model_metric_projection_failure("non_mapping_probability_container"),
        }
    out: ModelMetricRecord = {}
    ordered = sorted(items, key=mapping_pair_sort_key)
    for idx, (key, metric) in enumerate(ordered):
        if idx >= limit:
            out["_truncated"] = True
            break
        out_key, key_reason = json_key_result(key, idx)
        if key_reason:
            out[out_key] = projection_failure(key_reason, key)
            continue
        if out_key in _MODEL_FAILURE_KEYS:
            out[out_key] = _bounded_probability_side_evidence(metric)
            continue
        if metric is None:
            out[out_key] = None
            continue
        probability = exact_finite_float_or_none(metric)
        if probability is None:
            if type(metric) is float and not math.isfinite(metric):
                out[out_key] = model_metric_projection_failure("non_finite_probability")
            else:
                out[out_key] = model_metric_projection_failure("non_numeric_probability")
        elif not 0.0 <= probability <= 1.0:
            out[out_key] = model_metric_projection_failure("out_of_bounds_probability")
        else:
            out[out_key] = probability
    return out


def bounded_probability_mapping_for_final_json(value: ModelMetricValue, limit: int = 12) -> ModelMetricRecord:
    items = final_json_mapping_items(value)
    if items is None:
        return {
            "_unavailable_mapping": model_metric_projection_failure("non_mapping_probability_container"),
        }
    out: ModelMetricRecord = {}
    ordered = sorted(items, key=mapping_pair_sort_key)
    for idx, (key, metric) in enumerate(ordered):
        if idx >= limit:
            out["_truncated"] = True
            break
        out_key, key_reason = json_key_result(key, idx)
        if key_reason:
            out[out_key] = projection_failure(key_reason, key)
            continue
        if out_key in _MODEL_FAILURE_KEYS:
            out[out_key] = _bounded_probability_side_evidence(metric)
            continue
        if metric is None:
            out[out_key] = None
            continue
        probability = exact_finite_float_or_none(metric)
        if probability is None:
            reason = "non_finite_probability" if type(metric) is float and not math.isfinite(metric) else "non_numeric_probability"
            out[out_key] = None
            out[unavailable_reason_field(out_key)] = reason
        elif not 0.0 <= probability <= 1.0:
            out[out_key] = None
            out[unavailable_reason_field(out_key)] = "out_of_bounds_probability"
        else:
            out[out_key] = probability
    return out


__all__ = (
    "bounded_probability_mapping",
    "bounded_probability_mapping_for_final_json",
    "is_model_probability_mapping_key",
    "is_model_probability_metric_key",
    "model_metric_projection_failure",
)
