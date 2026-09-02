from __future__ import annotations

import json

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def test_stage1365_secondary_valid_feature_probability_is_not_dropped_by_primary_source() -> None:
    record = {
        "file": "stage1365-secondary-valid-probability.exe",
        "path": "stage1365-secondary-valid-probability.exe",
        "classification": "medium",
        "score": 53.0,
        "tags": ["stage1365_secondary_valid_probability"],
        "feature_probabilities": {
            "markov": 0.25,
        },
        "adaptive_learning": {
            "profile_coordinated": {
                "feature_probabilities": {
                    "profile": 0.625,
                },
            },
        },
    }

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]

    assert evidence["feature_probabilities"]["markov"] == 0.25
    assert evidence["feature_probabilities"]["profile"] == 0.625
    assert "unavailable_reasons" not in evidence
    assert "model_failures" not in evidence
    assert evidence["final_json_must_record"] is False
    assert evidence["replay_record_required"] is False
    assert validate_evidence_object_invariants(compact, context="stage1365-secondary-valid") is True
    json.dumps(compact, allow_nan=False, sort_keys=True)


def test_stage1365_secondary_probability_does_not_replace_invalid_primary_claim() -> None:
    record = {
        "file": "stage1365-secondary-does-not-clean-primary.exe",
        "path": "stage1365-secondary-does-not-clean-primary.exe",
        "classification": "medium",
        "score": 54.0,
        "tags": ["stage1365_secondary_no_clean_primary"],
        "feature_probabilities": {
            "profile": 1.5,
        },
        "adaptive_learning": {
            "profile_coordinated": {
                "feature_probabilities": {
                    "profile": 0.4,
                    "cluster": 0.3,
                },
            },
        },
    }

    projected = build_model_evidence_final_json_fields(record)["model_evidence"]

    probabilities = projected["feature_probabilities"]
    assert "profile" not in probabilities
    assert probabilities["cluster"] == 0.3
    assert projected["unavailable_reasons"]["profile"] == "out_of_bounds_probability"
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "profile_probability"
        and failure["reason"] == "out_of_bounds_probability"
        for failure in projected["model_failures"]
    )
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
    json.dumps(projected, allow_nan=False, sort_keys=True)
