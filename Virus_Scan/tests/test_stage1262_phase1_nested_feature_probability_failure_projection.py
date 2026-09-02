from __future__ import annotations

import math

from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1262_nested_feature_probability_failures_are_final_json_visible() -> None:
    compact = compact_result_record(
        {
            "file": "nested-probability.exe",
            "path": "nested-probability.exe",
            "classification": "suspicious",
            "score": 86.0,
            "tags": ["nested_model_probability_signal"],
            "explanation": {"reasons": ["nested model probabilities were output-affecting"]},
            "feature_probabilities": {"temporal": 0.25},
            "layered_detection": {
                "score": 86.0,
                "feature_probabilities": {"graph": math.inf},
            },
            "adaptive_learning": {
                "version": "adaptive_weights_v1_profile_markov_cluster",
                "feature_probabilities": {"profile": -0.1},
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"]["temporal"] == 0.25
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["unavailable_reasons"]["layered_detection.feature_probabilities.graph"] == "non_finite_probability"
    assert evidence["unavailable_reasons"]["adaptive_learning.feature_probabilities.profile"] == "out_of_bounds_probability"

    failures = evidence["model_failures"]
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "layered_detection.feature_probabilities.graph"
        and failure["affected_fields"] == ("layered_detection.feature_probabilities", "graph")
        for failure in failures
    )
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "adaptive_learning.feature_probabilities.profile"
        and failure["affected_fields"] == ("adaptive_learning.feature_probabilities", "profile")
        for failure in failures
    )


def test_stage1262_secondary_metadata_probabilities_are_not_hidden_by_direct_source() -> None:
    compact = compact_result_record(
        {
            "file": "secondary-metadata-probability.exe",
            "path": "secondary-metadata-probability.exe",
            "classification": "suspicious",
            "score": 81.0,
            "tags": ["secondary_metadata_model_probability_signal"],
            "explanation": {"reasons": ["secondary calibration probability was invalid"]},
            "feature_probabilities": {"markov": 0.4},
            "score_metadata": {
                "feature_probabilities": {"temporal": math.nan},
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"]["markov"] == 0.4
    assert evidence["unavailable_reasons"]["score_metadata.feature_probabilities.temporal"] == "non_finite_probability"
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "score_metadata.feature_probabilities.temporal"
        for failure in evidence["model_failures"]
    )
