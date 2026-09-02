from __future__ import annotations

import json

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1279_upstream_model_evidence_feature_probability_control_fields_are_not_preserved() -> None:
    compact = compact_result_record(
        {
            "file": "upstream-feature-control-fields.exe",
            "path": "upstream-feature-control-fields.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["upstream_feature_probability_control_fields"],
            "model_evidence": {
                "feature_probabilities": {
                    "markov": 0.2,
                    "_unavailable_reason": "cold_start",
                    "profile_unavailable_reason": "",
                    "model_failure": {
                        "model_name": "cluster",
                        "failure_type": "cold_start",
                        "reason": "unassigned_cluster",
                    },
                },
                "final_json_must_record": True,
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.2}
    assert "_unavailable_reason" not in evidence["feature_probabilities"]
    assert "profile_unavailable_reason" not in evidence["feature_probabilities"]
    assert "model_failure" not in evidence["feature_probabilities"]
    assert evidence["unavailable_reasons"] == {
        "model_evidence.feature_probabilities._unavailable_reason": "blank_model_unavailable_reason_key",
        "model_evidence.feature_probabilities.profile_unavailable_reason": "empty_model_unavailable_reason",
    }
    assert any(
        failure.get("model_name") == "cluster"
        and failure.get("failure_type") == "cold_start"
        for failure in evidence["model_failures"]
    )
    assert any(
        failure.get("model_name") == "model_evidence.feature_probabilities._unavailable_reason"
        and failure.get("reason") == "blank_model_unavailable_reason_key"
        for failure in evidence["model_failures"]
    )
    assert any(
        failure.get("model_name") == "model_evidence.feature_probabilities.profile_unavailable_reason"
        and failure.get("reason") == "empty_model_unavailable_reason"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1279") is True
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1279_upstream_model_evidence_unknown_feature_probability_field_is_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "upstream-unknown-feature-probability.exe",
            "path": "upstream-unknown-feature-probability.exe",
            "classification": "suspicious",
            "score": 85.0,
            "tags": ["upstream_unknown_feature_probability"],
            "model_evidence": {
                "feature_probabilities": {
                    "temporal": 0.35,
                    "unknown_model": "not-a-canonical-probability-field",
                },
                "final_json_must_record": True,
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"temporal": 0.35}
    assert evidence["unavailable_reasons"] == {
        "model_evidence.feature_probabilities.unknown_model": "unknown_model_probability_field"
    }
    assert {failure["model_name"] for failure in evidence["model_failures"]} == {
        "model_evidence.feature_probabilities.unknown_model"
    }
    assert {failure["failure_type"] for failure in evidence["model_failures"]} == {
        "invalid_existing_feature_probability_field"
    }
    assert validate_evidence_object_invariants(compact, context="stage1279") is True
    json.dumps(evidence, sort_keys=True, allow_nan=False)
