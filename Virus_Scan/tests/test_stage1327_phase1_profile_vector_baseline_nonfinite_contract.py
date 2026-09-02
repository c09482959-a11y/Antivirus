import json
import math

from Virus_Scan.models.profiles import vector_baseline_anomaly
from Virus_Scan.models.profiles.vector_statistics import default_profile_vector_statistics


from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
def _assert_strict_json_safe(record):
    json.dumps(record, sort_keys=True, allow_nan=False)


def _canonical_baseline(count=8, *, mean=0.1, variance=0.01):
    baseline = default_profile_vector_statistics()
    baseline["count"] = count
    baseline["trusted_count"] = count if type(count) is int else 8
    baseline["clean_diversity_keys"] = ["fixture:a", "fixture:b", "fixture:c"]
    baseline["clean_diversity_count"] = 3
    baseline["mean"] = [mean] * len(PROFILE_RAW_FEATURE_NAMES)
    baseline["variance"] = [variance] * len(PROFILE_RAW_FEATURE_NAMES)
    return baseline


def test_profile_vector_baseline_rejects_nonfinite_count_as_unavailable_evidence():
    baseline = _canonical_baseline()
    baseline["count"] = math.inf
    record = vector_baseline_anomaly(baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES))

    assert record["ready"] is False
    assert record["anomaly"] == 0.0
    assert record["reason"] == "invalid_vector_baseline_count"
    assert record["unavailable_reason"] == "invalid_vector_baseline_count"
    assert record["count"] == 0
    assert record["evidence_type"] == "profile_vector_baseline"
    assert record["profile_model_version"]
    assert record["degraded"] is True
    assert record["final_json_must_record"] is True
    assert record["replay_record_required"] is True
    assert record["model_failures"][0]["reason"] == "invalid_vector_baseline_count"
    assert record["model_failures"][0]["output_affecting"] is True
    _assert_strict_json_safe(record)


def test_profile_vector_baseline_rejects_nonfinite_mean_variance_and_vector_values():
    cases = []
    baseline = _canonical_baseline(mean=math.nan)
    cases.append((baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES)))
    baseline = _canonical_baseline(variance=math.inf)
    cases.append((baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES)))
    cases.append((_canonical_baseline(), [math.inf] + [0.1] * (len(PROFILE_RAW_FEATURE_NAMES) - 1)))
    for baseline, vector in cases:
        record = vector_baseline_anomaly(baseline, vector)

        assert record["ready"] is False
        assert record["anomaly"] == 0.0
        assert record["reason"] == "non_finite_profile_vector_baseline"
        assert record["count"] == 8
        assert record["dimension"] == 0
        _assert_strict_json_safe(record)


def test_profile_vector_baseline_rejects_negative_variance_without_fake_anomaly():
    record = vector_baseline_anomaly(
        _canonical_baseline(variance=-1.0),
        [0.5] * len(PROFILE_RAW_FEATURE_NAMES),
    )

    assert record["ready"] is False
    assert record["anomaly"] == 0.0
    assert record["reason"] == "invalid_profile_vector_variance"
    assert record["count"] == 8
    assert record["dimension"] == 0
    _assert_strict_json_safe(record)


def test_profile_vector_baseline_preserves_valid_finite_anomaly_behavior():
    baseline = _canonical_baseline(mean=0.2, variance=0.04)
    record = vector_baseline_anomaly(
        baseline,
        [0.8, 0.1] + [0.2] * (len(PROFILE_RAW_FEATURE_NAMES) - 2),
    )

    assert record["ready"] is True
    assert record["count"] == 8
    assert record["trusted_count"] == 8
    assert 0.0 <= record["anomaly"] <= 1.0
    assert record["avg_z"] > 0.0
    assert record["max_z"] > 0.0
    _assert_strict_json_safe(record)
