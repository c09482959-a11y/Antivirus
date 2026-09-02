import json
from unittest.mock import patch
import math

from Virus_Scan.detection.correlation.temporal import timeline as detection_timeline
from Virus_Scan.models.profiles import api as profile_models
from Virus_Scan.models.profiles import timeline as profile_timeline


def _detection_baseline(count):
    return {
        "timeline_baseline": {
            "sample_count": 10,
            "event_counts": {"benign_event": count},
            "transition_counts": {},
            "behavior_counts": {"other_behavior": 10},
            "behavior_transition_counts": {},
        }
    }


def _profile_baseline(count):
    return {
        "timeline_baseline": {
            "sample_count": 10,
            "event_counts": {"benign_event": count},
            "transition_counts": {},
            "behavior_counts": {"other": 10},
            "behavior_transition_counts": {},
        }
    }


def test_detection_timeline_rejects_nonfinite_event_count():
    with patch.object(
        detection_timeline,
        "read_extension_baseline_snapshot",
        lambda engine, file_path: _detection_baseline(math.inf),
    ):
        result = detection_timeline.extension_timeline_anomaly("renpy", "game.rpy", ["benign_event"])

    assert result["ready"] is False
    assert result["degraded"] is True
    assert result["anomaly"] == 0.0
    assert result["reason"] == "non_finite_timeline_event_count"
    assert result["failure_evidence"][0]["json_record_required"] is True
    json.dumps(result, allow_nan=False, sort_keys=True)


def test_profile_timeline_rejects_nonfinite_event_count():
    with patch.object(
        profile_timeline,
        "get_extension_baseline",
        lambda engine, file_path: _profile_baseline(float("nan")),
    ):
        result = profile_models.extension_timeline_anomaly("renpy", "game.rpy", ["benign_event"])

    assert result["ready"] is False
    assert result["degraded"] is True
    assert result["anomaly"] == 0.0
    assert result["reason"] == "non_finite_timeline_event_count"
    assert result["final_json_must_record"] is True
    assert result["replay_record_required"] is True
    json.dumps(result, allow_nan=False, sort_keys=True)


def test_profile_and_detection_timeline_preserve_finite_counts():
    with (
        patch.object(
            detection_timeline,
            "read_extension_baseline_snapshot",
            lambda engine, file_path: _detection_baseline(10),
        ),
        patch.object(
            profile_timeline,
            "get_extension_baseline",
            lambda engine, file_path: _profile_baseline(10),
        ),
    ):
        detection_result = detection_timeline.extension_timeline_anomaly("renpy", "game.rpy", ["benign_event"])
        profile_result = profile_models.extension_timeline_anomaly("renpy", "game.rpy", ["benign_event"])

    assert detection_result["ready"] is True
    assert profile_result["ready"] is True
    assert detection_result["anomaly"] == 0.0
    assert profile_result["anomaly"] == 0.0
    json.dumps(detection_result, allow_nan=False, sort_keys=True)
    json.dumps(profile_result, allow_nan=False, sort_keys=True)
