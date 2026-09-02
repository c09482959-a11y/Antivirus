from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1272_direct_non_mapping_feature_probabilities_is_result_boundary_invalid() -> None:
    record = {
        "file": "invalid-feature-probabilities.exe",
        "path": "invalid-feature-probabilities.exe",
        "classification": "suspicious",
        "score": 84.0,
        "feature_probabilities": "not-a-feature-probability-record",
    }

    with pytest.raises(ValueError, match=r"feature_probabilities.*feature probabilities record must be an object"):
        validate_evidence_object_invariants(record, context="stage1272")


def test_stage1272_model_evidence_non_mapping_feature_probabilities_is_result_boundary_invalid() -> None:
    record = {
        "file": "invalid-nested-feature-probabilities.exe",
        "path": "invalid-nested-feature-probabilities.exe",
        "classification": "suspicious",
        "score": 84.0,
        "model_evidence": {
            "feature_probabilities": "not-a-feature-probability-record",
            "final_json_must_record": True,
        },
    }

    with pytest.raises(ValueError, match=r"model_evidence\.feature_probabilities.*feature probabilities record must be an object"):
        validate_evidence_object_invariants(record, context="stage1272")


def test_stage1272_direct_non_mapping_feature_probabilities_becomes_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "invalid-feature-probabilities.exe",
            "path": "invalid-feature-probabilities.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["feature_probability_signal"],
            "explanation": {"reasons": ["feature probability record affected model evidence"]},
            "feature_probabilities": "not-a-feature-probability-record",
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["unavailable_reasons"]["feature_probabilities"] == "non_mapping_feature_probability_record"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_failures"] == (
        {
            "model_name": "feature_probabilities",
            "failure_type": "invalid_feature_probability_record",
            "reason": "non_mapping_feature_probability_record",
            "affected_fields": ("feature_probabilities",),
            "model_version": "model_evidence_writer_v1",
            "details": {
                "source_field": "feature_probabilities",
                "value_type": "str",
                "value_repr": "'not-a-feature-probability-record'",
            },
        },
    )


def test_stage1272_nested_non_mapping_feature_probabilities_becomes_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "nested-invalid-feature-probabilities.exe",
            "path": "nested-invalid-feature-probabilities.exe",
            "classification": "suspicious",
            "score": 79.0,
            "tags": ["nested_feature_probability_signal"],
            "score_metadata": {
                "feature_probabilities": "not-a-feature-probability-record",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert (
        evidence["unavailable_reasons"]["score_metadata.feature_probabilities"]
        == "non_mapping_feature_probability_record"
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_failures"][0]["model_name"] == "score_metadata.feature_probabilities"
    assert evidence["model_failures"][0]["failure_type"] == "invalid_feature_probability_record"
    assert evidence["model_failures"][0]["reason"] == "non_mapping_feature_probability_record"


def test_stage1272_upstream_model_evidence_non_mapping_feature_probabilities_becomes_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "upstream-invalid-feature-probabilities.exe",
            "path": "upstream-invalid-feature-probabilities.exe",
            "classification": "suspicious",
            "score": 79.0,
            "tags": ["upstream_feature_probability_signal"],
            "model_evidence": {
                "feature_probabilities": "not-a-feature-probability-record",
                "final_json_must_record": True,
                "writer_version": "upstream_writer_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["writer_version"] == "upstream_writer_v1"
    assert (
        evidence["unavailable_reasons"]["model_evidence.feature_probabilities"]
        == "non_mapping_feature_probability_record"
    )
    assert "feature_probabilities" not in evidence
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_failures"][0]["model_name"] == "model_evidence.feature_probabilities"
