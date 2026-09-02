"""Stage 1660: profile support counts must not silently truncate decimals."""

from __future__ import annotations

from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES

from Virus_Scan.models.profiles.baseline import profile_model_unavailable
from Virus_Scan.models.profiles.common import profile_int
from Virus_Scan.models.profiles.timeline import profile_timeline_unavailable
from Virus_Scan.models.profiles.vector_anomaly import vector_baseline_anomaly
from Virus_Scan.models.profiles.vector_statistics import default_profile_vector_statistics


def test_stage1660_profile_int_rejects_non_integral_float_without_truncation() -> None:
    assert profile_int(2.9, default=7) == 7
    assert profile_int(2.0, default=7) == 2
    assert profile_int("2.9", default=7) == 7


def test_stage1660_profile_unavailable_count_rejects_non_integral_support_metric() -> None:
    vector = profile_model_unavailable("profile_count_probe", count=2.9)
    timeline = profile_timeline_unavailable("timeline_count_probe", sample_count=3.7)

    assert vector["count"] == 0
    assert vector["reason"] == "profile_count_probe"
    assert vector["final_json_must_record"] is True
    assert timeline["sample_count"] == 0
    assert timeline["reason"] == "timeline_count_probe"
    assert timeline["final_json_must_record"] is True


def test_stage1660_vector_baseline_count_rejects_decimal_count_instead_of_truncating() -> None:
    baseline = default_profile_vector_statistics()
    baseline["count"] = 5.9
    baseline["trusted_count"] = 5
    baseline["clean_diversity_keys"] = ["fixture:a", "fixture:b", "fixture:c"]
    baseline["clean_diversity_count"] = 3
    baseline["mean"] = [0.1] * len(PROFILE_RAW_FEATURE_NAMES)
    baseline["variance"] = [0.01] * len(PROFILE_RAW_FEATURE_NAMES)
    record = vector_baseline_anomaly(baseline, [0.2] * len(PROFILE_RAW_FEATURE_NAMES))

    assert record["ready"] is False
    assert record["reason"] == "invalid_vector_baseline_count"
    assert record["unavailable_reason"] == "invalid_vector_baseline_count"
    assert record["count"] == 0
    assert record["final_json_must_record"] is True


def test_stage1660_integral_float_counts_preserve_existing_unavailable_count_semantics() -> None:
    vector = profile_model_unavailable("profile_count_probe", count=2.0)
    timeline = profile_timeline_unavailable("timeline_count_probe", sample_count=3.0)

    assert vector["count"] == 2
    assert timeline["sample_count"] == 3
