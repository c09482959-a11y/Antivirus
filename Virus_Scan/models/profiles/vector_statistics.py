"""Profile-owned deterministic robust vector-statistics mutation."""
from __future__ import annotations

import math
from typing import Final

from Virus_Scan.models.profiles.feature_registry import (
    PROFILE_RAW_FEATURE_NAMES,
    PROFILE_RAW_FEATURE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.maturity import profile_maturity_evidence

PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION: Final[str] = "profile_vector_statistics_v3"
PROFILE_VECTOR_HISTOGRAM_BINS: Final[int] = 21
PROFILE_MAX_OBSERVATION_INFLUENCE: Final[float] = 0.25
_MAX_CLEAN_DIVERSITY_KEYS: Final[int] = 256
_VECTOR_STATISTICS_KEYS: Final[frozenset[str]] = frozenset((
    "schema_version", "feature_schema_version", "feature_names", "count",
    "trusted_count", "clean_diversity_keys", "clean_diversity_count",
    "mean", "m2", "variance", "histograms", "q25", "median", "q75",
    "p95", "outlier_count", "quarantine_count", "update_ordinal",
    "maximum_observation_influence", "maturity", "suppression_authority",
    "minimum_support", "minimum_clean_diversity",
))


def _empty_histograms() -> list[list[int]]:
    return [
        [0] * PROFILE_VECTOR_HISTOGRAM_BINS
        for _name in PROFILE_RAW_FEATURE_NAMES
    ]


def default_profile_vector_statistics() -> dict[str, object]:
    baseline: dict[str, object] = {
        "schema_version": PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION,
        "feature_schema_version": PROFILE_RAW_FEATURE_SCHEMA_VERSION,
        "feature_names": list(PROFILE_RAW_FEATURE_NAMES),
        "count": 0,
        "trusted_count": 0,
        "clean_diversity_keys": [],
        "clean_diversity_count": 0,
        "mean": [],
        "m2": [],
        "variance": [],
        "histograms": _empty_histograms(),
        "q25": [],
        "median": [],
        "q75": [],
        "p95": [],
        "outlier_count": 0,
        "quarantine_count": 0,
        "update_ordinal": 0,
        "maximum_observation_influence": PROFILE_MAX_OBSERVATION_INFLUENCE,
    }
    _publish_maturity(baseline)
    return baseline


def _publish_maturity(baseline: dict[str, object]) -> None:
    maturity = profile_maturity_evidence(baseline)
    baseline.update({
        "maturity": maturity["maturity"],
        "suppression_authority": maturity["suppression_authority"],
        "minimum_support": dict(maturity["minimum_support"]),
        "minimum_clean_diversity": dict(maturity["minimum_clean_diversity"]),
    })


def _finite_vector(vector: object) -> list[float]:
    if type(vector) not in (list, tuple):
        raise ValueError("profile_raw_feature_vector_invalid")
    if len(vector) != len(PROFILE_RAW_FEATURE_NAMES):
        raise ValueError("profile_raw_feature_vector_shape_invalid")
    values: list[float] = []
    for value in vector:
        if type(value) is bool or type(value) not in (int, float):
            raise ValueError("profile_raw_feature_vector_value_invalid")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ValueError("profile_raw_feature_vector_non_finite")
        if numeric < 0.0 or numeric > 1.0:
            raise ValueError("profile_raw_feature_vector_out_of_bounds")
        values.append(numeric)
    return values


def _finite_stat_vector(value: object, *, empty_allowed: bool) -> list[float]:
    if empty_allowed and value in ([], ()):
        return [0.0] * len(PROFILE_RAW_FEATURE_NAMES)
    return _finite_vector(value)


def _histograms(value: object) -> list[list[int]]:
    if type(value) is not list or len(value) != len(PROFILE_RAW_FEATURE_NAMES):
        raise ValueError("profile_vector_histograms_invalid")
    result: list[list[int]] = []
    for histogram in value:
        if type(histogram) is not list or len(histogram) != PROFILE_VECTOR_HISTOGRAM_BINS:
            raise ValueError("profile_vector_histogram_shape_invalid")
        if any(type(item) is not int or type(item) is bool or item < 0 for item in histogram):
            raise ValueError("profile_vector_histogram_count_invalid")
        result.append(list(histogram))
    return result


def _diversity_keys(value: object, trusted: int) -> list[str]:
    if (
        type(value) is not list
        or any(type(key) is not str or key == "" for key in value)
        or value != sorted(set(value))
        or len(value) > min(_MAX_CLEAN_DIVERSITY_KEYS, trusted)
    ):
        raise ValueError("profile_clean_diversity_invalid")
    return list(value)


def _current_statistics(baseline: object) -> tuple[object, ...]:
    if type(baseline) is not dict:
        raise ValueError("profile_vector_statistics_invalid")
    if baseline.get("schema_version") != PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION:
        raise ValueError("profile_vector_statistics_schema_invalid")
    if frozenset(baseline) != _VECTOR_STATISTICS_KEYS:
        raise ValueError("profile_vector_statistics_fields_invalid")
    if baseline.get("feature_schema_version") != PROFILE_RAW_FEATURE_SCHEMA_VERSION:
        raise ValueError("profile_vector_feature_schema_invalid")
    if tuple(baseline.get("feature_names", ())) != PROFILE_RAW_FEATURE_NAMES:
        raise ValueError("profile_vector_feature_registry_invalid")
    count = baseline.get("count", 0)
    trusted = baseline.get("trusted_count", 0)
    outliers = baseline.get("outlier_count", 0)
    quarantined = baseline.get("quarantine_count", 0)
    update_ordinal = baseline.get("update_ordinal", 0)
    for value in (count, trusted, outliers, quarantined, update_ordinal):
        if type(value) is not int or type(value) is bool or value < 0:
            raise ValueError("profile_vector_statistics_count_invalid")
    if trusted > count or update_ordinal < count:
        raise ValueError("profile_vector_trusted_count_invalid")
    diversity = _diversity_keys(baseline.get("clean_diversity_keys"), trusted)
    if baseline.get("clean_diversity_count") != len(diversity):
        raise ValueError("profile_clean_diversity_invalid")
    mean = _finite_stat_vector(baseline.get("mean", ()), empty_allowed=trusted == 0)
    m2 = _finite_stat_vector(baseline.get("m2", ()), empty_allowed=trusted == 0)
    histograms = _histograms(baseline.get("histograms"))
    return (
        count, trusted, diversity, mean, m2, histograms,
        outliers, quarantined, update_ordinal,
    )


def _histogram_quantile(histogram: list[int], quantile: float) -> float:
    support = sum(histogram)
    if support == 0:
        return 0.0
    target = max(1, math.ceil(support * quantile))
    seen = 0
    for index, count in enumerate(histogram):
        seen += count
        if seen >= target:
            return index / (PROFILE_VECTOR_HISTOGRAM_BINS - 1)
    return 1.0


def _bounded_observation(values: list[float], mean: list[float], trusted: int) -> tuple[list[float], bool]:
    if trusted == 0:
        return values, False
    bounded: list[float] = []
    clipped = False
    for value, expected in zip(values, mean, strict=True):
        delta = value - expected
        if delta > PROFILE_MAX_OBSERVATION_INFLUENCE:
            value = expected + PROFILE_MAX_OBSERVATION_INFLUENCE
            clipped = True
        elif delta < -PROFILE_MAX_OBSERVATION_INFLUENCE:
            value = expected - PROFILE_MAX_OBSERVATION_INFLUENCE
            clipped = True
        bounded.append(min(1.0, max(0.0, value)))
    return bounded, clipped



def validate_profile_vector_statistics(value: object) -> bool:
    current = _current_statistics(value)
    _count, trusted, _diversity, _mean, _m2, _histograms, _outliers, _quarantined, _ordinal = current
    for key in ("variance", "q25", "median", "q75", "p95"):
        _finite_stat_vector(value.get(key, ()), empty_allowed=trusted == 0)
    if value.get("maximum_observation_influence") != PROFILE_MAX_OBSERVATION_INFLUENCE:
        raise ValueError("profile_vector_influence_contract_invalid")
    profile_maturity_evidence(value)
    return True

def update_profile_vector_statistics(
    baseline: object, vector: object, *, diversity_key: str,
) -> dict[str, object]:
    """Return the next bounded trusted statistics snapshot."""
    if type(diversity_key) is not str or diversity_key == "":
        raise ValueError("profile_clean_diversity_key_required")
    values = _finite_vector(vector)
    current = _current_statistics(baseline)
    count, trusted, diversity, mean, m2, histograms, outliers, quarantined, ordinal = current
    bounded_values, clipped = _bounded_observation(values, mean, trusted)
    next_count = count + 1
    next_trusted = trusted + 1
    for index, value in enumerate(bounded_values):
        delta = value - mean[index]
        mean[index] += delta / next_trusted
        delta2 = value - mean[index]
        m2[index] += delta * delta2
        bin_index = min(
            PROFILE_VECTOR_HISTOGRAM_BINS - 1,
            int(value * (PROFILE_VECTOR_HISTOGRAM_BINS - 1)),
        )
        histograms[index][bin_index] += 1
    if diversity_key not in diversity:
        diversity.append(diversity_key)
        diversity = sorted(diversity)[-_MAX_CLEAN_DIVERSITY_KEYS:]
    variance = [
        m2[index] / max(1, next_trusted - 1) if next_trusted > 1 else 0.0
        for index in range(len(bounded_values))
    ]
    result: dict[str, object] = {
        "schema_version": PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION,
        "feature_schema_version": PROFILE_RAW_FEATURE_SCHEMA_VERSION,
        "feature_names": list(PROFILE_RAW_FEATURE_NAMES),
        "count": next_count,
        "trusted_count": next_trusted,
        "clean_diversity_keys": diversity,
        "clean_diversity_count": len(diversity),
        "mean": mean,
        "m2": m2,
        "variance": variance,
        "histograms": histograms,
        "q25": [_histogram_quantile(histogram, 0.25) for histogram in histograms],
        "median": [_histogram_quantile(histogram, 0.50) for histogram in histograms],
        "q75": [_histogram_quantile(histogram, 0.75) for histogram in histograms],
        "p95": [_histogram_quantile(histogram, 0.95) for histogram in histograms],
        "outlier_count": outliers + int(clipped),
        "quarantine_count": quarantined,
        "update_ordinal": ordinal + 1,
        "maximum_observation_influence": PROFILE_MAX_OBSERVATION_INFLUENCE,
    }
    _publish_maturity(result)
    return result


def record_profile_vector_quarantine(baseline: object) -> dict[str, object]:
    """Record one blocked observation without mutating benign statistics."""
    current = _current_statistics(baseline)
    count, trusted, diversity, mean, m2, histograms, outliers, quarantined, ordinal = current
    result = dict(baseline)
    result.update({
        "count": count + 1,
        "trusted_count": trusted,
        "clean_diversity_keys": diversity,
        "clean_diversity_count": len(diversity),
        "mean": mean if trusted else [],
        "m2": m2 if trusted else [],
        "histograms": histograms,
        "outlier_count": outliers,
        "quarantine_count": quarantined + 1,
        "update_ordinal": ordinal + 1,
    })
    _publish_maturity(result)
    return result


__all__ = (
    "PROFILE_MAX_OBSERVATION_INFLUENCE",
    "PROFILE_VECTOR_HISTOGRAM_BINS",
    "PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION",
    "default_profile_vector_statistics",
    "record_profile_vector_quarantine",
    "update_profile_vector_statistics",
    "validate_profile_vector_statistics",
)
