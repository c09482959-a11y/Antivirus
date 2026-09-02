from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1282_direct_feature_probability_model_failure_record_alias_is_contract_valid() -> None:
    record = {
        "file": "direct-feature-probability-failure-record-contract.exe",
        "path": "direct-feature-probability-failure-record-contract.exe",
        "classification": "suspicious",
        "score": 82.0,
        "tags": ["feature_probability_failure_record_contract"],
        "feature_probabilities": {
            "markov": 0.41,
            "model_failure_record": {
                "model_name": "temporal",
                "failure_type": "cold_start",
                "reason": "missing_temporal_snapshot",
            },
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1282-direct") is True

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.41}
    assert any(
        failure.get("model_name") == "temporal"
        and failure.get("failure_type") == "cold_start"
        and failure.get("reason") == "missing_temporal_snapshot"
        for failure in evidence["model_failures"]
    )


def test_stage1282_nested_feature_probability_model_failures_alias_is_contract_valid() -> None:
    record = {
        "file": "nested-feature-probability-failures-contract.exe",
        "path": "nested-feature-probability-failures-contract.exe",
        "classification": "suspicious",
        "score": 83.0,
        "tags": ["nested_feature_probability_failures_contract"],
        "explanation": {
            "feature_probabilities": {
                "cluster": 0.58,
                "model_failures": (
                    {
                        "model_name": "cluster",
                        "failure_type": "degraded_state",
                        "reason": "centroid_snapshot_unavailable",
                    },
                    {
                        "model_name": "graph",
                        "failure_type": "replay_mismatch",
                        "reason": "relationship_evidence_changed",
                    },
                ),
            },
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1282-nested") is True

    compact = compact_result_record(record)
    projected = {
        (failure.get("model_name"), failure.get("failure_type"), failure.get("reason"))
        for failure in compact["model_evidence"]["model_failures"]
    }
    assert ("cluster", "degraded_state", "centroid_snapshot_unavailable") in projected
    assert ("graph", "replay_mismatch", "relationship_evidence_changed") in projected


def test_stage1282_upstream_model_evidence_feature_probability_model_failures_alias_is_contract_valid() -> None:
    record = {
        "file": "upstream-feature-probability-failures-contract.exe",
        "path": "upstream-feature-probability-failures-contract.exe",
        "classification": "suspicious",
        "score": 84.0,
        "tags": ["upstream_feature_probability_failures_contract"],
        "model_evidence": {
            "feature_probabilities": {
                "temporal": 0.47,
                "model_failures": [
                    {
                        "model_name": "profile",
                        "failure_type": "corrupt_state",
                        "reason": "invalid_profile_schema",
                    }
                ],
            },
            "final_json_must_record": True,
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1282-upstream") is True

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"temporal": 0.47}
    assert any(
        failure.get("model_name") == "profile"
        and failure.get("failure_type") == "corrupt_state"
        and failure.get("reason") == "invalid_profile_schema"
        for failure in evidence["model_failures"]
    )


def test_stage1282_malformed_feature_probability_failure_alias_is_contract_invalid_as_failure_record() -> None:
    record = {
        "file": "malformed-feature-probability-failure-alias-contract.exe",
        "path": "malformed-feature-probability-failure-alias-contract.exe",
        "classification": "suspicious",
        "score": 85.0,
        "tags": ["malformed_feature_probability_failure_alias_contract"],
        "feature_probabilities": {
            "markov": 0.35,
            "model_failures": ["not-a-model-failure-record"],
        },
    }

    with pytest.raises(
        ValueError,
        match=r"feature_probabilities\.model_failures\[0\].*model failure record must be an object",
    ):
        validate_evidence_object_invariants(record, context="stage1282-malformed")


def test_stage1282_direct_and_upstream_feature_probability_model_failures_alias_are_contract_valid() -> None:
    record = {
        "file": "mixed-direct-upstream-feature-probability-failures-contract.exe",
        "path": "mixed-direct-upstream-feature-probability-failures-contract.exe",
        "classification": "suspicious",
        "score": 86.0,
        "tags": ["mixed_direct_upstream_feature_probability_failures_contract"],
        "feature_probabilities": {"markov": 0.36},
        "model_evidence": {
            "feature_probabilities": {
                "temporal": 0.49,
                "model_failures": [
                    {
                        "model_name": "profile",
                        "failure_type": "corrupt_state",
                        "reason": "invalid_profile_schema",
                    }
                ],
            }
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1282-mixed") is True

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"temporal": 0.49, "markov": 0.36}
    assert "model_failures" not in evidence["feature_probabilities"]
    assert any(
        failure.get("model_name") == "profile"
        and failure.get("failure_type") == "corrupt_state"
        and failure.get("reason") == "invalid_profile_schema"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1282-mixed-compact") is True
