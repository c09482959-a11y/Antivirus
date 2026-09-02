from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from pathlib import Path
from unittest.mock import patch

from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.models.profiles import baseline as profile_baseline
from Virus_Scan.models.profiles.request_contracts import ProfileBucketValidationRequest
from Virus_Scan.models.profiles import vector_anomaly as profile_vector_anomaly
from Virus_Scan.models.profiles.vector_statistics import default_profile_vector_statistics


from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
class HostileNumeric:
    touched = 0

    def __float__(self):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("profile vector owner must not call caller-owned float")

    def __int__(self):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("profile vector owner must not call caller-owned int")


class HostileBaseline(dict):
    touched = 0

    def get(self, key, default=None):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("profile vector owner must not call caller-owned mapping get")


def _reset() -> None:
    HostileNumeric.touched = 0
    HostileBaseline.touched = 0


def _canonical_baseline():
    baseline = default_profile_vector_statistics()
    baseline["count"] = 5
    baseline["trusted_count"] = 5
    baseline["clean_diversity_keys"] = ["fixture:a", "fixture:b", "fixture:c"]
    baseline["clean_diversity_count"] = 3
    baseline["mean"] = [0.1] * len(PROFILE_RAW_FEATURE_NAMES)
    baseline["variance"] = [1.0] * len(PROFILE_RAW_FEATURE_NAMES)
    return baseline


def test_stage2023_vector_baseline_rejects_hostile_numeric_without_float_hooks() -> None:
    _reset()
    baseline = _canonical_baseline()
    baseline["mean"][0] = HostileNumeric()
    record = profile_vector_anomaly.vector_baseline_anomaly(baseline, [0.2] * len(PROFILE_RAW_FEATURE_NAMES))

    assert record["ready"] is False
    assert record["unavailable_reason"] == "non_finite_profile_vector_baseline"
    assert record["count"] == 5
    assert record["final_json_must_record"] is True
    assert HostileNumeric.touched == 0


def test_stage2023_vector_baseline_rejects_hostile_mapping_without_get_hooks() -> None:
    _reset()
    record = profile_vector_anomaly.vector_baseline_anomaly(
        HostileBaseline(_canonical_baseline()),
        [0.2] * len(PROFILE_RAW_FEATURE_NAMES),
    )

    assert record["ready"] is False
    assert record["unavailable_reason"] == "invalid_vector_baseline"
    assert HostileBaseline.touched == 0


def test_stage2023_vector_baseline_preserves_exact_primitive_anomaly() -> None:
    record = profile_vector_anomaly.vector_baseline_anomaly(
        _canonical_baseline(),
        [0.2] * len(PROFILE_RAW_FEATURE_NAMES),
    )

    assert record["ready"] is True
    assert record["count"] == 5
    assert 0.0 <= record["anomaly"] <= 1.0


def test_stage2023_profile_bucket_validation_uses_explicit_aggregate_bounds() -> None:
    with patch.object(profile_baseline, "HIGH_RISK_BUCKETS", frozenset({"credential"})):
        result = profile_baseline.profile_behavior_bucket_validation(
            ProfileBucketValidationRequest(
                "renpy", "sample.rpy", physical_tag_evidence(("credential_dump",)),
            )
        )

    assert result["blocked"] is True
    assert result["allow_learning"] is False
    assert 0.0 <= result["bucket_anomaly"] <= 1.0

    source = read_python_file(Path("Virus_Scan/models/profiles/baseline.py"))
    vector_source = read_python_file(Path("Virus_Scan/models/profiles/vector_anomaly.py"))
    assert "def _profile_model_finite_float" not in source
    assert "profile_finite_float(value, None)" in vector_source
    assert "vector_baseline.get(" not in vector_source
    assert "blocked = bool(" not in source
    assert "safe_clamp(sum(bucket_scores)" not in source
