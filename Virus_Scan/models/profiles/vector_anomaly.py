"""Canonical profile raw-vector anomaly evidence owner."""
from __future__ import annotations

import math

from Virus_Scan.models.profiles.baseline import profile_model_unavailable
from Virus_Scan.models.profiles.common import (
    profile_finite_float,
    profile_mapping_get,
    profile_ratio,
)
from Virus_Scan.models.profiles.feature_registry import (
    PROFILE_RAW_FEATURE_NAMES,
    PROFILE_RAW_FEATURE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.maturity import profile_maturity_evidence
from Virus_Scan.models.profiles.vector_statistics import (
    PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION,
)


def _canonical_support(vector_baseline: object) -> object:
    if type(vector_baseline) is not dict:
        return profile_model_unavailable("invalid_vector_baseline")
    if profile_mapping_get(vector_baseline, "schema_version") != PROFILE_VECTOR_STATISTICS_SCHEMA_VERSION:
        return profile_model_unavailable("invalid_vector_baseline_schema")
    if profile_mapping_get(vector_baseline, "feature_schema_version") != PROFILE_RAW_FEATURE_SCHEMA_VERSION:
        return profile_model_unavailable("invalid_vector_feature_schema")
    if tuple(profile_mapping_get(vector_baseline, "feature_names", ())) != PROFILE_RAW_FEATURE_NAMES:
        return profile_model_unavailable("invalid_vector_feature_registry")
    count = profile_mapping_get(vector_baseline, "count")
    if type(count) is not int or type(count) is bool or count < 0:
        return profile_model_unavailable("invalid_vector_baseline_count")
    trusted = profile_mapping_get(vector_baseline, "trusted_count")
    if type(trusted) is not int or type(trusted) is bool or trusted < 0 or trusted > count:
        return profile_model_unavailable(
            "invalid_vector_baseline_trusted_count", count=count,
        )
    return count, trusted


def _vector_baseline_values(
    vector_baseline: dict[str, object], vector: object, count: int,
) -> object:
    mean = profile_mapping_get(vector_baseline, "mean")
    variance = profile_mapping_get(vector_baseline, "variance")
    if type(mean) not in (list, tuple) or type(variance) not in (list, tuple):
        return profile_model_unavailable("invalid_vector_baseline_shape", count=count)
    if type(vector) not in (list, tuple):
        return profile_model_unavailable("invalid_vector_baseline_shape", count=count)
    dimension = len(PROFILE_RAW_FEATURE_NAMES)
    if len(mean) != dimension or len(variance) != dimension or len(vector) != dimension:
        return profile_model_unavailable("invalid_vector_baseline_shape", count=count)
    return mean, variance, vector


def _vector_baseline_z_metrics(
    mean: object, variance: object, vector: object, count: int,
) -> object:
    zsum = 0.0
    maxz = 0.0
    for index, (value, expected, spread) in enumerate(
        zip(vector, mean, variance, strict=True)
    ):
        vector_value = profile_finite_float(value, None)
        mean_value = profile_finite_float(expected, None)
        variance_value = profile_finite_float(spread, None)
        if vector_value is None or mean_value is None or variance_value is None:
            return profile_model_unavailable(
                "non_finite_profile_vector_baseline",
                count=count, dimension=index,
            )
        if variance_value < 0.0:
            return profile_model_unavailable(
                "invalid_profile_vector_variance", count=count, dimension=index,
            )
        z = abs(vector_value - mean_value) / (variance_value ** 0.5 + 0.05)
        if not math.isfinite(z):
            return profile_model_unavailable(
                "non_finite_profile_vector_anomaly",
                count=count, dimension=index,
            )
        zsum += min(z, 6.0)
        maxz = max(maxz, z)
    return zsum, maxz


def vector_baseline_anomaly(vector_baseline: object, vector: object) -> object:
    """Return strict schema-bound, maturity-limited vector anomaly evidence."""
    support = _canonical_support(vector_baseline)
    if type(support) is dict:
        return support
    count, trusted_count = support
    maturity = profile_maturity_evidence(vector_baseline)
    if maturity["ready"] is not True:
        return profile_model_unavailable(
            maturity["reason"] or "profile_vector_maturity_unavailable",
            count=trusted_count,
        )
    values = _vector_baseline_values(vector_baseline, vector, trusted_count)
    if type(values) is dict:
        return values
    mean, variance, safe_vector = values
    metrics = _vector_baseline_z_metrics(mean, variance, safe_vector, trusted_count)
    if type(metrics) is dict:
        return metrics
    zsum, maxz = metrics
    avgz = zsum / len(PROFILE_RAW_FEATURE_NAMES)
    if not math.isfinite(avgz) or not math.isfinite(maxz):
        return profile_model_unavailable(
            "non_finite_profile_vector_anomaly", count=trusted_count,
        )
    raw_anomaly = profile_ratio(avgz, 3.0)
    return {
        "ready": True,
        "anomaly": raw_anomaly * maturity["suppression_authority"],
        "raw_anomaly": raw_anomaly,
        "avg_z": avgz,
        "max_z": maxz,
        "count": count,
        "trusted_count": trusted_count,
        "maturity": maturity["maturity"],
        "suppression_authority": maturity["suppression_authority"],
    }


__all__ = ("vector_baseline_anomaly",)
