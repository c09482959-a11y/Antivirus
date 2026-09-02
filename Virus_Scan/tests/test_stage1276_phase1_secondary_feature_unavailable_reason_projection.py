from __future__ import annotations

import json
import math

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1276_nested_feature_unavailable_reason_value_is_result_boundary_invalid() -> None:
    record = {
        "file": "nested-invalid-feature-unavailable-reason.exe",
        "path": "nested-invalid-feature-unavailable-reason.exe",
        "classification": "suspicious",
        "score": 80.0,
        "score_metadata": {
            "feature_probabilities": {
                "profile": 0.32,
                "profile_unavailable_reason": {"reason": "missing_profile"},
            }
        },
    }

    with pytest.raises(
        ValueError,
        match=r"score_metadata\.feature_probabilities\.profile_unavailable_reason.*unavailable reason",
    ):
        validate_evidence_object_invariants(record, context="stage1276")


def test_stage1276_secondary_feature_unavailable_reasons_are_replay_visible() -> None:
    compact = compact_result_record(
        {
            "file": "secondary-feature-unavailable-reason.exe",
            "path": "secondary-feature-unavailable-reason.exe",
            "classification": "suspicious",
            "score": 83.0,
            "tags": ["secondary_feature_unavailable_reason_signal"],
            "explanation": {"reasons": ["secondary feature unavailable reasons affected model evidence"]},
            "feature_probabilities": {
                "markov": 0.42,
                "markov_unavailable_reason": "cold_start",
            },
            "score_metadata": {
                "feature_probabilities": {
                    "profile": 0.65,
                    "profile_unavailable_reason": " missing_profile ",
                    "cluster_unavailable_reason": "",
                    "temporal_unavailable_reason": math.nan,
                }
            },
            "model_context": {
                "feature_probabilities": {
                    "graph_unavailable_reason": " graph_snapshot_missing ",
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.42}
    assert evidence["unavailable_reasons"] == {
        "markov": "cold_start",
        "model_context.feature_probabilities.graph": "graph_snapshot_missing",
        "score_metadata.feature_probabilities.cluster_unavailable_reason": "empty_model_unavailable_reason",
        "score_metadata.feature_probabilities.profile": "missing_profile",
        "score_metadata.feature_probabilities.temporal_unavailable_reason": "non_text_model_unavailable_reason",
    }
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence["model_failures"]
    assert {failure["model_name"] for failure in failures} == {
        "score_metadata.feature_probabilities.cluster_unavailable_reason",
        "score_metadata.feature_probabilities.temporal_unavailable_reason",
    }
    assert {failure["failure_type"] for failure in failures} == {"invalid_model_unavailable_reason"}
    assert {failure["reason"] for failure in failures} == {
        "empty_model_unavailable_reason",
        "non_text_model_unavailable_reason",
    }
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1276_secondary_reasons_do_not_override_primary_reasons() -> None:
    compact = compact_result_record(
        {
            "file": "secondary-does-not-override-primary.exe",
            "path": "secondary-does-not-override-primary.exe",
            "classification": "medium",
            "score": 55.0,
            "feature_probabilities": {
                "temporal": 0.31,
                "temporal_unavailable_reason": "primary_reason",
            },
            "adaptive_score_metadata": {
                "feature_probabilities": {
                    "temporal_unavailable_reason": "secondary_reason",
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["unavailable_reasons"] == {
        "adaptive_score_metadata.feature_probabilities.temporal": "secondary_reason",
        "temporal": "primary_reason",
    }
    assert "model_failures" not in evidence
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
