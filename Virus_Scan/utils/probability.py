"""Direct-import-safe probability/scoring helpers."""
from __future__ import annotations

import math
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float

ANALYTICAL_EVIDENCE_SCHEMA_VERSION = 2
PROBABILISTIC_SEMANTICS_VERSION = "probabilistic_semantics_v1"
RELIABILITY_TO_NUMERIC: Mapping[str, float] = MappingProxyType({
    "deterministic": 0.95,
    "strong_heuristic": 0.82,
    "medium_heuristic": 0.62,
    "weak_heuristic": 0.35,
    "contextual": 0.20,
})
EVIDENCE_STRENGTH_TO_LIKELIHOOD: Mapping[str, float] = MappingProxyType({
    "deterministic": 0.92,
    "strong_heuristic": 0.78,
    "medium_heuristic": 0.56,
    "weak_heuristic": 0.30,
    "contextual": 0.18,
})


def _bounded_probability(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    lower = lo if math.isfinite(lo) else 0.0
    upper = hi if math.isfinite(hi) else 1.0
    if lower > upper:
        lower, upper = upper, lower
    if not math.isfinite(value):
        return lower
    return max(lower, min(upper, value))


def safe_clamp(x: object, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp finite numeric model values without promoting corrupt values.

    Python's ``min``/``max`` ordering can turn ``NaN`` into the upper bound,
    which makes corrupt model evidence look maximally confident.  Non-finite
    or non-numeric values are treated as unavailable numeric input and project
    to the lower bound; callers that expose output-affecting evidence remain
    responsible for publishing the corresponding unavailable/degraded reason.
    """
    lower, lower_reason = no_hook_finite_float(lo, default=0.0, reason="invalid_clamp_lower_bound", non_finite_reason="invalid_clamp_lower_bound")
    upper, upper_reason = no_hook_finite_float(hi, default=1.0, reason="invalid_clamp_upper_bound", non_finite_reason="invalid_clamp_upper_bound")
    if lower_reason:
        lower = 0.0
    if upper_reason:
        upper = 1.0
    if lower > upper:
        lower, upper = upper, lower
    value, value_reason = no_hook_finite_float(x, default=lower, reason="invalid_clamp_value", non_finite_reason="invalid_clamp_value")
    if value_reason:
        return lower
    return _bounded_probability(value, lower, upper)


def safe_probability_score(value: object) -> float:
    """Clamp exact numeric probability-like scores without accepting bools."""
    if type(value) is bool:
        return 0.0
    if type(value) in (int, float):
        return safe_clamp(value)
    return 0.0


def calibrated_sigmoid_probability(logit_value: object, temperature: float = 1.0) -> float:
    """Numerically stable public sigmoid for probability/log-odds fusion.

    Non-finite logits or temperatures are corrupt model inputs.  They must not
    saturate into 1.0/0.0 confidence as if they were learned evidence; callers
    that surface output-affecting evidence remain responsible for recording the
    unavailable/degraded reason.
    """
    raw_logit, logit_reason = no_hook_finite_float(logit_value, default=0.0, reason="invalid_logit", non_finite_reason="invalid_logit")
    raw_temperature, temperature_reason = no_hook_finite_float(temperature, default=1.0, reason="invalid_temperature", non_finite_reason="invalid_temperature")
    if logit_reason or temperature_reason:
        return 0.0
    x = raw_logit / max(1e-6, raw_temperature)
    if not math.isfinite(x):
        return 0.0
    if x >= 0:
        z = math.exp(-x)
        return _bounded_probability(1.0 / (1.0 + z))
    z = math.exp(x)
    return _bounded_probability(z / (1.0 + z))


def centered_sigmoid_probability(value: object, midpoint: float = 0.0, scale: float = 1.0, min_scale: float = 1e-9) -> float:
    """Numerically stable public sigmoid centered around an arbitrary midpoint.

    Invalid numeric input is treated as unavailable probability and bounded to
    0.0 by the shared probability contract.
    """
    min_scale_value, min_scale_reason = no_hook_finite_float(min_scale, default=1e-9, reason="invalid_min_scale", non_finite_reason="invalid_min_scale")
    scale_value, scale_reason = no_hook_finite_float(scale, default=1.0, reason="invalid_scale", non_finite_reason="invalid_scale")
    value_number, value_reason = no_hook_finite_float(value, default=0.0, reason="invalid_sigmoid_value", non_finite_reason="invalid_sigmoid_value")
    midpoint_value, midpoint_reason = no_hook_finite_float(midpoint, default=0.0, reason="invalid_midpoint", non_finite_reason="invalid_midpoint")
    if min_scale_reason or scale_reason or value_reason or midpoint_reason:
        return 0.0
    denominator = max(min_scale_value, scale_value)
    return calibrated_sigmoid_probability((value_number - midpoint_value) / denominator)


def safe_logit_probability(probability: object) -> float:
    """Convert a bounded probability-like value into stable log odds."""
    value, reason = no_hook_finite_float(probability, default=0.0, reason="invalid_logit_probability", non_finite_reason="invalid_logit_probability")
    if reason:
        return 0.0
    p = _bounded_probability(value, 1e-5, 1.0 - 1e-5)
    return math.log(p / (1.0 - p))


def score_to_probability(score: object, midpoint: float = 50.0, scale: float = 14.0) -> float:
    score_value, score_reason = no_hook_finite_float(score, default=0.0, reason="invalid_score", non_finite_reason="invalid_score")
    midpoint_value, midpoint_reason = no_hook_finite_float(midpoint, default=50.0, reason="invalid_midpoint", non_finite_reason="invalid_midpoint")
    scale_value, scale_reason = no_hook_finite_float(scale, default=14.0, reason="invalid_scale", non_finite_reason="invalid_scale")
    if score_reason or midpoint_reason or scale_reason:
        return 0.0
    logit = (score_value - midpoint_value) / max(1e-6, scale_value)
    return calibrated_sigmoid_probability(logit)


def sigmoid_score_100(raw_value: object, midpoint: float = 50.0, scale: float = 12.0) -> float:
    """Numerically stable sigmoid mapped to a 0..100 score."""
    value, value_reason = no_hook_finite_float(raw_value, default=0.0, reason="invalid_score", non_finite_reason="invalid_score")
    midpoint_value, midpoint_reason = no_hook_finite_float(midpoint, default=50.0, reason="invalid_midpoint", non_finite_reason="invalid_midpoint")
    scale_value, scale_reason = no_hook_finite_float(scale, default=12.0, reason="invalid_scale", non_finite_reason="invalid_scale")
    if value_reason or midpoint_reason or scale_reason:
        return 0.0
    logit = (value - midpoint_value) / max(1e-6, scale_value)
    return _bounded_probability(calibrated_sigmoid_probability(logit) * 100.0, 0.0, 100.0)


__all__ = (
    "ANALYTICAL_EVIDENCE_SCHEMA_VERSION",
    "EVIDENCE_STRENGTH_TO_LIKELIHOOD",
    "PROBABILISTIC_SEMANTICS_VERSION",
    "RELIABILITY_TO_NUMERIC",
    "calibrated_sigmoid_probability",
    "centered_sigmoid_probability",
    "safe_clamp",
    "safe_logit_probability",
    "safe_probability_score",
    "score_to_probability",
    "sigmoid_score_100",
)
