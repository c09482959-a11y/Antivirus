from __future__ import annotations

import json

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def test_stage1363_deep_nested_feature_probability_source_reaches_final_json() -> None:
    record = {
        "file": "stage1363-deep-nested-feature-probability.exe",
        "path": "stage1363-deep-nested-feature-probability.exe",
        "classification": "medium",
        "score": 48.0,
        "tags": ["stage1363_deep_nested_feature_probability"],
        "adaptive_learning": {
            "profile_coordinated": {
                "feature_probabilities": {
                    "profile": 0.375,
                },
            },
        },
    }

    projected = build_model_evidence_final_json_fields(record)["model_evidence"]

    assert projected["feature_probabilities"]["profile"] == 0.375
    assert projected["final_json_must_record"] is False
    assert projected["replay_record_required"] is False
    json.dumps(projected, allow_nan=False, sort_keys=True)


def test_stage1363_deep_nested_feature_unavailable_reason_is_not_dropped_by_primary_source() -> None:
    record = {
        "file": "stage1363-deep-nested-unavailable-reason.exe",
        "path": "stage1363-deep-nested-unavailable-reason.exe",
        "classification": "medium",
        "score": 49.0,
        "tags": ["stage1363_deep_nested_feature_unavailable_reason"],
        "feature_probabilities": {
            "markov": 0.25,
        },
        "adaptive_learning": {
            "profile_coordinated": {
                "feature_probabilities": {
                    "temporal_unavailable_reason": "insufficient_temporal_history",
                    "graph": 1.25,
                },
            },
        },
    }

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    unavailable = evidence["unavailable_reasons"]

    assert evidence["feature_probabilities"]["markov"] == 0.25
    assert (
        unavailable["adaptive_learning.profile_coordinated.feature_probabilities.temporal"]
        == "insufficient_temporal_history"
    )
    assert unavailable["adaptive_learning.profile_coordinated.feature_probabilities.graph"] == "out_of_bounds_probability"
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "adaptive_learning.profile_coordinated.feature_probabilities.graph"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1363-compact") is True
    json.dumps(compact, allow_nan=False, sort_keys=True)


def test_stage1363_invalid_deep_nested_feature_unavailable_reason_shape_becomes_failure() -> None:
    record = {
        "file": "stage1363-invalid-deep-nested-unavailable-reason.exe",
        "path": "stage1363-invalid-deep-nested-unavailable-reason.exe",
        "classification": "medium",
        "score": 50.0,
        "tags": ["stage1363_invalid_deep_nested_feature_unavailable_reason"],
        "feature_probabilities": {
            "markov": 0.2,
        },
        "adaptive_learning": {
            "profile_coordinated": {
                "feature_probabilities": {
                    "cluster_unavailable_reason": ["not", "text"],
                },
            },
        },
    }

    projected = build_model_evidence_final_json_fields(record)["model_evidence"]

    assert projected["unavailable_reasons"][
        "adaptive_learning.profile_coordinated.feature_probabilities.cluster_unavailable_reason"
    ] == "non_text_model_unavailable_reason"
    assert any(
        failure["failure_type"] == "invalid_model_unavailable_reason"
        and failure["model_name"] == "adaptive_learning.profile_coordinated.feature_probabilities.cluster_unavailable_reason"
        for failure in projected["model_failures"]
    )
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
    json.dumps(projected, allow_nan=False, sort_keys=True)
