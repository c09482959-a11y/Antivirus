import json
import math

from Virus_Scan.models.replay.api import result_learning_payload
from Virus_Scan.models.replay_economics import (
    ReplayEconomicsConfig,
    replay_compress_metadata,
    replay_should_retain,
)


def test_parent_replay_learning_payload_sanitizes_nonfinite_score_for_model_inputs():
    result = {
        "file": "game/script.rpy",
        "classification": "benign_clean",
        "tags": ["process_exec", "network_fetch"],
        "score": float("nan"),
        "engine_context": {"other": 1.0},
        "ordered_events": ["process_exec", "network_fetch"],
        "scan_integrity": {"allow_learning": True},
    }

    payload = result_learning_payload(result)

    assert payload is not None
    assert payload["score"] == 0.0
    assert payload["degraded"] is True
    assert payload["replay_score_unavailable_reason"] == "non_finite_replay_score"
    assert "vector" not in payload
    json.dumps(payload, sort_keys=True, allow_nan=False)


def test_parent_replay_learning_payload_sanitizes_infinite_score_before_vector_build():
    result = {
        "file": "game/script.rpy",
        "classification": "benign_clean",
        "tags": ["process_exec"],
        "score_100": float("inf"),
        "engine_context": {"other": 1.0},
        "behavior_flow": ["process_exec"],
        "scan_integrity": {"allow_learning": True},
    }

    payload = result_learning_payload(result)

    assert payload is not None
    assert payload["score"] == 0.0
    assert payload["replay_score_unavailable_reason"] == "non_finite_replay_score"
    json.dumps(payload, sort_keys=True, allow_nan=False)


def test_replay_retention_does_not_keep_nonfinite_score_as_high_value_model_evidence():
    rare_sample_config = ReplayEconomicsConfig(sample_modulo=10_000, divergence_always_keep=False)

    assert replay_should_retain({"score": float("inf")}, index=1, config=rare_sample_config) is False
    assert replay_should_retain({"score": float("nan")}, index=1, config=rare_sample_config) is False
    assert replay_should_retain({"score": 25.0}, index=1, config=rare_sample_config) is True


def test_replay_metadata_compression_materializes_nonfinite_values_as_unavailable_evidence():
    compressed = replay_compress_metadata({
        "runtime": {"score": float("nan"), "belief": float("inf")},
        "learning": [1.0, float("-inf")],
    })

    assert compressed["runtime"]["score"] == {"value": None, "unavailable_reason": "non_finite_replay_metadata"}
    assert compressed["runtime"]["belief"] == {"value": None, "unavailable_reason": "non_finite_replay_metadata"}
    assert compressed["learning"][1] == {"value": None, "unavailable_reason": "non_finite_replay_metadata"}
    json.dumps(compressed, sort_keys=True, allow_nan=False)
