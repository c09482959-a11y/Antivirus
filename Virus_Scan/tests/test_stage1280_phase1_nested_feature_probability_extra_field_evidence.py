from __future__ import annotations

import json

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1280_direct_feature_probability_unknown_field_is_degraded_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "direct-feature-extra.exe",
            "path": "direct-feature-extra.exe",
            "classification": "suspicious",
            "score": 82.0,
            "tags": ["direct_feature_probability_extra"],
            "feature_probabilities": {
                "markov": 0.4,
                "unknown_model": "not-a-probability",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.4}
    assert evidence["unavailable_reasons"] == {
        "feature_probabilities.unknown_model": "unknown_model_probability_field"
    }
    assert any(
        failure.get("model_name") == "feature_probabilities.unknown_model"
        and failure.get("failure_type") == "invalid_existing_feature_probability_field"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1280-direct") is True
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1280_secondary_feature_probability_extra_fields_are_not_silently_dropped() -> None:
    compact = compact_result_record(
        {
            "file": "secondary-feature-extra.exe",
            "path": "secondary-feature-extra.exe",
            "classification": "suspicious",
            "score": 83.0,
            "tags": ["secondary_feature_probability_extra"],
            "feature_probabilities": {"markov": 0.3},
            "explanation": {
                "feature_probabilities": {
                    "temporal": 0.5,
                    "unknown_model": "not-a-canonical-model-probability",
                    "model_failure": {
                        "model_name": "cluster",
                        "failure_type": "cold_start",
                        "reason": "unassigned_cluster",
                    },
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.3}
    assert evidence["unavailable_reasons"] == {
        "explanation.feature_probabilities.unknown_model": "unknown_model_probability_field"
    }
    assert any(
        failure.get("model_name") == "explanation.feature_probabilities.unknown_model"
        and failure.get("failure_type") == "invalid_existing_feature_probability_field"
        for failure in evidence["model_failures"]
    )
    assert any(
        failure.get("model_name") == "cluster"
        and failure.get("failure_type") == "cold_start"
        and failure.get("reason") == "unassigned_cluster"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1280-secondary") is True
    json.dumps(evidence, sort_keys=True, allow_nan=False)
