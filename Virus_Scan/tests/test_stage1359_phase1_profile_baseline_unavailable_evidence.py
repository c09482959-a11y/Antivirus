import pytest
import json
from unittest.mock import patch

from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.models import profiles as profile_models
from Virus_Scan.models.profiles import vector_baseline_anomaly
from Virus_Scan.models.profiles.vector_statistics import default_profile_vector_statistics


from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES

@pytest.fixture(autouse=True)
def _canonical_profile_bootstrap(tmp_path):
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()


def _assert_unavailable_model_evidence(record, reason, evidence_type):
    assert record["ready"] is False
    assert record["anomaly"] == 0.0
    assert record["reason"] == reason
    assert record["unavailable_reason"] == reason
    assert record["degraded"] is True
    assert record["evidence_type"] == evidence_type
    assert record["final_json_must_record"] is True
    assert record["replay_record_required"] is True
    assert record["model_failures"][0]["reason"] == reason
    assert record["model_failures"][0]["output_affecting"] is True
    json.dumps(record, sort_keys=True, allow_nan=False)


def _canonical_baseline(count):
    baseline = default_profile_vector_statistics()
    baseline["count"] = count
    baseline["trusted_count"] = count
    diversity = min(count, 3)
    baseline["clean_diversity_keys"] = [f"fixture:{index}" for index in range(diversity)]
    baseline["clean_diversity_count"] = diversity
    baseline["mean"] = [0.1] * len(PROFILE_RAW_FEATURE_NAMES)
    baseline["variance"] = [0.01] * len(PROFILE_RAW_FEATURE_NAMES)
    return baseline


def test_profile_vector_baseline_cold_start_is_output_affecting_unavailable_evidence():
    record = vector_baseline_anomaly(_canonical_baseline(1), [0.2] * len(PROFILE_RAW_FEATURE_NAMES))

    _assert_unavailable_model_evidence(
        record,
        "insufficient_trusted_profile_support",
        "profile_vector_baseline",
    )
    assert record["count"] == 1
    assert record["profile_model_version"]


def test_profile_vector_baseline_invalid_shape_is_output_affecting_unavailable_evidence():
    baseline = _canonical_baseline(8)
    baseline["mean"] = "not-a-vector"
    record = vector_baseline_anomaly(baseline, [0.2] * len(PROFILE_RAW_FEATURE_NAMES))

    _assert_unavailable_model_evidence(
        record,
        "invalid_vector_baseline_shape",
        "profile_vector_baseline",
    )
    assert record["count"] == 8


def test_profile_timeline_cold_start_is_output_affecting_unavailable_evidence():
    with patch.object(
        profile_models,
        "get_extension_baseline",
        lambda engine, file_path: {
            "timeline_baseline": {
                "sample_count": 0,
                "event_counts": {},
                "transition_counts": {},
                "behavior_counts": {},
                "behavior_transition_counts": {},
            }
        },
    ):
        record = profile_models.extension_timeline_anomaly("renpy", "game.rpy", ["benign_event"])

    _assert_unavailable_model_evidence(
        record,
        "insufficient_timeline_history",
        "profile_timeline_baseline",
    )
    assert record["sample_count"] == 0
