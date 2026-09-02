from __future__ import annotations

import json

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def test_stage1366_secondary_valid_probability_survives_degraded_reason_control_field() -> None:
    record = {
        "file": "stage1366-secondary-mixed-degraded.exe",
        "path": "stage1366-secondary-mixed-degraded.exe",
        "classification": "medium",
        "score": 55.0,
        "tags": ["stage1366_secondary_mixed_degraded"],
        "feature_probabilities": {
            "markov": 0.24,
        },
        "adaptive_learning": {
            "profile_coordinated": {
                "feature_probabilities": {
                    "profile": 0.71,
                    "temporal_unavailable_reason": "insufficient_temporal_history",
                },
            },
        },
    }

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]

    assert evidence["feature_probabilities"]["markov"] == 0.24
    assert evidence["feature_probabilities"]["profile"] == 0.71
    assert evidence["unavailable_reasons"][
        "adaptive_learning.profile_coordinated.feature_probabilities.temporal"
    ] == "insufficient_temporal_history"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1366-secondary-mixed-degraded") is True
    json.dumps(compact, allow_nan=False, sort_keys=True)


def test_stage1366_secondary_valid_probability_survives_unknown_field_failure_evidence() -> None:
    record = {
        "file": "stage1366-secondary-mixed-unknown.exe",
        "path": "stage1366-secondary-mixed-unknown.exe",
        "classification": "medium",
        "score": 56.0,
        "tags": ["stage1366_secondary_mixed_unknown"],
        "feature_probabilities": {
            "markov": 0.31,
        },
        "adaptive_learning": {
            "profile_coordinated": {
                "feature_probabilities": {
                    "cluster": 0.44,
                    "opaque_payload": {"must_not_be_probability": True},
                },
            },
        },
    }

    projected = build_model_evidence_final_json_fields(record)["model_evidence"]

    assert projected["feature_probabilities"]["markov"] == 0.31
    assert projected["feature_probabilities"]["cluster"] == 0.44
    source = "adaptive_learning.profile_coordinated.feature_probabilities.opaque_payload"
    assert projected["unavailable_reasons"][source] == "unknown_model_probability_field"
    assert any(
        failure["failure_type"] == "invalid_existing_feature_probability_field"
        and failure["model_name"] == source
        and failure["reason"] == "unknown_model_probability_field"
        for failure in projected["model_failures"]
    )
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
    json.dumps(projected, allow_nan=False, sort_keys=True)
