from __future__ import annotations

import json

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1281_direct_feature_probability_model_failure_record_alias_is_projected() -> None:
    compact = compact_result_record(
        {
            "file": "direct-feature-failure-record-alias.exe",
            "path": "direct-feature-failure-record-alias.exe",
            "classification": "suspicious",
            "score": 82.0,
            "tags": ["direct_feature_probability_failure_alias"],
            "feature_probabilities": {
                "markov": 0.42,
                "model_failure_record": {
                    "model_name": "temporal",
                    "failure_type": "cold_start",
                    "reason": "missing_temporal_snapshot",
                },
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.42}
    assert "model_failure_record" not in evidence["feature_probabilities"]
    assert any(
        failure.get("model_name") == "temporal"
        and failure.get("failure_type") == "cold_start"
        and failure.get("reason") == "missing_temporal_snapshot"
        for failure in evidence["model_failures"]
    )
    assert not any(
        failure.get("model_name") == "feature_probabilities.model_failure_record"
        and failure.get("failure_type") == "invalid_existing_feature_probability_field"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1281-direct") is True
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1281_secondary_feature_probability_model_failures_alias_is_projected() -> None:
    compact = compact_result_record(
        {
            "file": "secondary-feature-failure-alias.exe",
            "path": "secondary-feature-failure-alias.exe",
            "classification": "suspicious",
            "score": 83.0,
            "tags": ["secondary_feature_probability_failure_alias"],
            "feature_probabilities": {"markov": 0.31},
            "explanation": {
                "feature_probabilities": {
                    "cluster": 0.55,
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
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.31}
    assert "explanation.feature_probabilities.model_failures" not in evidence.get("unavailable_reasons", {})
    projected = {
        (failure.get("model_name"), failure.get("failure_type"), failure.get("reason"))
        for failure in evidence["model_failures"]
    }
    assert ("cluster", "degraded_state", "centroid_snapshot_unavailable") in projected
    assert ("graph", "replay_mismatch", "relationship_evidence_changed") in projected
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1281-secondary") is True
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1281_upstream_model_evidence_feature_probability_failure_alias_is_projected() -> None:
    compact = compact_result_record(
        {
            "file": "upstream-feature-failure-alias.exe",
            "path": "upstream-feature-failure-alias.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["upstream_feature_probability_failure_alias"],
            "model_evidence": {
                "feature_probabilities": {
                    "temporal": 0.44,
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
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"temporal": 0.44}
    assert "model_failures" not in evidence["feature_probabilities"]
    assert any(
        failure.get("model_name") == "profile"
        and failure.get("failure_type") == "corrupt_state"
        and failure.get("reason") == "invalid_profile_schema"
        for failure in evidence["model_failures"]
    )
    assert not any(
        failure.get("model_name") == "model_evidence.feature_probabilities.model_failures"
        and failure.get("failure_type") == "invalid_existing_feature_probability_field"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1281-upstream") is True
    json.dumps(evidence, sort_keys=True, allow_nan=False)
