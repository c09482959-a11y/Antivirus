from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.profiles import anomaly_frequency
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.vector_statistics import (
    default_profile_vector_statistics,
    update_profile_vector_statistics,
)

from Virus_Scan.models.profiles import api as profile_api


class HostileProfileMapping(dict):
    touched = 0

    def get(self, key, default=None):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("profile API must not call caller-owned mapping get")

    def values(self):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("profile API must not call caller-owned mapping values")


def _mature_vector_baseline() -> dict[str, object]:
    baseline = default_profile_vector_statistics()
    for _ordinal in range(12):
        baseline = update_profile_vector_statistics(
            baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=f"api:{_ordinal}",
        )
    return baseline


def test_stage2023_behavior_bucket_frequency_preserves_exact_primitive_counts() -> None:
    baseline = {
        "files": 12,
        "vector_baseline": _mature_vector_baseline(),
        "behavior_buckets": {
            "os_execution": {"files": 9, "tags": {"shell": 2, "network": 1}},
        },
    }
    with patch.object(anomaly_frequency, "get_extension_baseline", return_value=baseline):
        record = profile_api.behavior_bucket_frequency_evidence(
            "renpy", "game.rpy", "os_execution",
        )
    assert record["ready"] is True
    assert record["successes"] == 9
    assert record["support"] == 12
    assert record["probability"] == 10 / 14

def test_stage2023_behavior_bucket_frequency_rejects_hostile_mapping_hooks() -> None:
    HostileProfileMapping.touched = 0
    baseline = HostileProfileMapping({"files": 4, "behavior_buckets": {}})
    with patch.object(anomaly_frequency, "get_extension_baseline", return_value=baseline):
        record = profile_api.behavior_bucket_frequency_evidence(
            "renpy", "game.rpy", "os_execution",
        )
    assert record["ready"] is False
    assert record["probability"] == 0.0
    assert HostileProfileMapping.touched == 0

def test_stage2023_profile_api_frequency_surface_has_no_duplicate_estimator() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/api.py"))

    assert "baseline.get(" not in source
    assert ".values()" not in source
    assert "def behavior_bucket_probability" not in source
    assert "laplace_beta_binomial_v1" not in source
