from __future__ import annotations

import json

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1277_direct_out_of_bounds_feature_probability_is_result_boundary_invalid() -> None:
    record = {
        "file": "direct-out-of-bounds-feature-probability.exe",
        "path": "direct-out-of-bounds-feature-probability.exe",
        "classification": "suspicious",
        "score": 82.0,
        "feature_probabilities": {
            "markov": 1.5,
            "temporal_unavailable_reason": "cold_start",
        },
    }

    with pytest.raises(ValueError, match=r"feature_probabilities\.markov.*probability out of bounds"):
        validate_evidence_object_invariants(record, context="stage1277")


def test_stage1277_nested_out_of_bounds_feature_probability_is_result_boundary_invalid() -> None:
    record = {
        "file": "nested-out-of-bounds-feature-probability.exe",
        "path": "nested-out-of-bounds-feature-probability.exe",
        "classification": "suspicious",
        "score": 84.0,
        "model_evidence": {
            "feature_probabilities": {
                "profile": -0.25,
                "model_failure": None,
            },
            "final_json_must_record": True,
        },
    }

    with pytest.raises(ValueError, match=r"model_evidence\.feature_probabilities\.profile.*probability out of bounds"):
        validate_evidence_object_invariants(record, context="stage1277")


def test_stage1277_non_numeric_feature_probability_is_result_boundary_invalid_without_blocking_failure_records() -> None:
    invalid_record = {
        "file": "non-numeric-feature-probability.exe",
        "path": "non-numeric-feature-probability.exe",
        "classification": "suspicious",
        "score": 85.0,
        "score_metadata": {
            "feature_probabilities": {
                "cluster": "not-a-probability",
                "cluster_unavailable_reason": "cluster_unassigned",
                "model_failure": {
                    "model_name": "cluster",
                    "failure_type": "cold_start",
                    "reason": "cluster_unassigned",
                },
            }
        },
    }

    with pytest.raises(ValueError, match=r"score_metadata\.feature_probabilities\.cluster.*probability must be numeric"):
        validate_evidence_object_invariants(invalid_record, context="stage1277")

    valid_record = dict(invalid_record)
    valid_record["score_metadata"] = {
        "feature_probabilities": {
            "cluster": 0.0,
            "cluster_unavailable_reason": "cluster_unassigned",
            "model_failure": {
                "model_name": "cluster",
                "failure_type": "cold_start",
                "reason": "cluster_unassigned",
            },
        }
    }
    assert validate_evidence_object_invariants(valid_record, context="stage1277") is True


def test_stage1277_publication_still_projects_invalid_feature_probabilities_as_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "publication-invalid-feature-probability.exe",
            "path": "publication-invalid-feature-probability.exe",
            "classification": "suspicious",
            "score": 86.0,
            "tags": ["feature_probability_boundary_bounds"],
            "explanation": {"reasons": ["feature probability bounds affected model evidence"]},
            "feature_probabilities": {
                "markov": 1.5,
                "temporal": 0.25,
            },
            "model_evidence": {
                "feature_probabilities": {
                    "profile": -0.1,
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"temporal": 0.25}
    assert evidence["unavailable_reasons"] == {
        "markov": "out_of_bounds_probability",
        "model_evidence.feature_probabilities.profile": "out_of_bounds_probability",
    }
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert {failure["model_name"] for failure in evidence["model_failures"]} == {
        "markov_probability",
        "model_evidence.feature_probabilities.profile",
    }
    json.dumps(evidence, sort_keys=True, allow_nan=False)
