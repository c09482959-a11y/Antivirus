from __future__ import annotations

import json

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def test_stage1364_malformed_deep_nested_feature_probability_container_becomes_evidence() -> None:
    record = {
        "file": "stage1364-malformed-deep-container.exe",
        "path": "stage1364-malformed-deep-container.exe",
        "classification": "medium",
        "score": 51.0,
        "tags": ["stage1364_malformed_deep_container"],
        "adaptive_learning": {
            "profile_coordinated": {
                "feature_probabilities": ["not", "a", "mapping"],
            },
        },
    }

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]

    source = "adaptive_learning.profile_coordinated.feature_probabilities"
    assert evidence["unavailable_reasons"][source] == "non_mapping_feature_probability_record"
    assert any(
        failure["failure_type"] == "invalid_feature_probability_record"
        and failure["model_name"] == source
        and failure["reason"] == "non_mapping_feature_probability_record"
        for failure in evidence["model_failures"]
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1364-deep-container") is True
    json.dumps(compact, allow_nan=False, sort_keys=True)


def test_stage1364_malformed_feature_probability_container_inside_signal_list_becomes_evidence() -> None:
    record = {
        "file": "stage1364-malformed-list-container.exe",
        "path": "stage1364-malformed-list-container.exe",
        "classification": "medium",
        "score": 52.0,
        "tags": ["stage1364_malformed_list_container"],
        "adaptive_learning": {
            "profile_segments": (
                {
                    "name": "segment-a",
                    "feature_probabilities": "not-a-mapping",
                },
            ),
        },
    }

    projected = build_model_evidence_final_json_fields(record)["model_evidence"]

    source = "adaptive_learning.profile_segments[0].feature_probabilities"
    assert projected["unavailable_reasons"][source] == "non_mapping_feature_probability_record"
    assert any(
        failure["failure_type"] == "invalid_feature_probability_record"
        and failure["model_name"] == source
        and failure["details"]["value_type"] == "str"
        for failure in projected["model_failures"]
    )
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
    json.dumps(projected, allow_nan=False, sort_keys=True)
