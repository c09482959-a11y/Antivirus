from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1270_direct_model_failure_string_is_result_boundary_invalid() -> None:
    record = {
        "file": "direct-invalid-model-failure.exe",
        "path": "direct-invalid-model-failure.exe",
        "classification": "suspicious",
        "score": 84.0,
        "model_failure": "not-a-model-failure-record",
    }

    with pytest.raises(ValueError, match=r"model_failure.*model failure record must be an object"):
        validate_evidence_object_invariants(record, context="stage1270")


def test_stage1270_direct_non_mapping_model_failure_becomes_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "direct-invalid-model-failure.exe",
            "path": "direct-invalid-model-failure.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["model_failure_signal"],
            "explanation": {"reasons": ["model failure record affected model evidence"]},
            "model_failure": "not-a-model-failure-record",
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["unavailable_reasons"]["model_failure"] == "non_mapping_model_failure_record"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_failures"] == (
        {
            "model_name": "model_failure",
            "failure_type": "invalid_model_failure_record",
            "reason": "non_mapping_model_failure_record",
            "affected_fields": ("model_failure",),
            "model_version": "model_evidence_writer_v1",
            "details": {
                "source_field": "model_failure",
                "value_type": "str",
                "value_repr": "'not-a-model-failure-record'",
            },
        },
    )


def test_stage1270_upstream_non_mapping_model_failures_are_sanitized() -> None:
    compact = compact_result_record(
        {
            "file": "upstream-invalid-model-failure.exe",
            "path": "upstream-invalid-model-failure.exe",
            "classification": "suspicious",
            "score": 79.0,
            "tags": ["upstream_model_failure_signal"],
            "explanation": {"reasons": ["upstream model failure record affected model evidence"]},
            "model_evidence": {
                "model_failures": [
                    {
                        "model_name": "profile_snapshot",
                        "failure_type": "invalid_profile",
                        "reason": "schema_version_mismatch",
                    },
                    "bad-upstream-failure-record",
                ],
                "writer_version": "upstream_writer_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["writer_version"] == "upstream_writer_v1"
    assert evidence["unavailable_reasons"]["model_evidence.model_failures[1]"] == "non_mapping_model_failure_record"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert [failure["failure_type"] for failure in evidence["model_failures"]] == [
        "invalid_profile",
        "invalid_model_failure_record",
    ]
    assert evidence["model_failures"][1]["model_name"] == "model_evidence.model_failures[1]"
    assert evidence["model_failures"][1]["reason"] == "non_mapping_model_failure_record"


def test_stage1270_probability_source_model_failure_missing_required_field_is_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "scoring-invalid-model-failure.exe",
            "path": "scoring-invalid-model-failure.exe",
            "classification": "suspicious",
            "score": 77.0,
            "tags": ["scoring_model_failure_signal"],
            "explanation": {"reasons": ["scoring model failure record affected model evidence"]},
            "score_metadata": {
                "feature_probabilities": {
                    "markov": 0.25,
                    "model_failure": {
                        "model_name": "adaptive_probability_features",
                        "reason": "missing failure type should not publish as valid evidence",
                    },
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.25}
    assert (
        evidence["unavailable_reasons"]["score_metadata.feature_probabilities.model_failure"]
        == "missing_failure_type"
    )
    assert evidence["model_failures"][0]["failure_type"] == "invalid_model_failure_record"
    assert evidence["model_failures"][0]["reason"] == "missing_failure_type"
