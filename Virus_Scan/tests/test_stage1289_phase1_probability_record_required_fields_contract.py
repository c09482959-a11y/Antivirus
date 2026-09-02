from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1289_direct_probability_record_missing_required_support_is_boundary_invalid() -> None:
    record = {
        "file": "missing-probability-support.exe",
        "path": "missing-probability-support.exe",
        "classification": "suspicious",
        "score": 74.0,
        "probability_record": {
            "ready": True,
            "probability": 0.9,
            "model_version": "probability_record_v1",
        },
    }

    with pytest.raises(ValueError, match=r"probability_record.*missing support"):
        validate_evidence_object_invariants(record, context="stage1289-source")


def test_stage1289_direct_probability_record_missing_required_fields_projects_degraded_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "missing-probability-fields.exe",
            "path": "missing-probability-fields.exe",
            "classification": "suspicious",
            "score": 77.0,
            "tags": ["probability_required_field_signal"],
            "explanation": {"reasons": ["probability record affected model evidence"]},
            "probability_record": {
                "ready": True,
                "probability": 0.9,
                "model_version": "probability_record_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert probability_record["probability"] == 0.9
    assert probability_record["support_unavailable_reason"] == "missing_probability_record_field"
    assert probability_record["count_unavailable_reason"] == "missing_probability_record_field"
    assert probability_record["vocab_unavailable_reason"] == "missing_probability_record_field"
    assert probability_record["smoothing_unavailable_reason"] == "missing_probability_record_field"
    assert probability_record["reason_unavailable_reason"] == "missing_probability_record_field"
    assert evidence["unavailable_reasons"]["probability_record.support"] == "missing_probability_record_field"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure.get("failure_type") == "invalid_model_contract_record_schema"
        and failure.get("model_name") == "probability_record.support"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1289-compact") is True


def test_stage1289_nested_markov_probability_record_missing_required_fields_is_validated_and_projected() -> None:
    record = {
        "file": "nested-missing-markov-support.bin",
        "path": "nested-missing-markov-support.bin",
        "classification": "suspicious",
        "score": 78.0,
        "adaptive_learning": {
            "markov_probability_record": {
                "ready": True,
                "probability": 0.75,
                "model_version": "markov_probability_v1",
            }
        },
    }

    with pytest.raises(ValueError, match=r"markov_probability_record.*missing support"):
        validate_evidence_object_invariants(record, context="stage1289-nested-source")

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    markov_record = evidence["markov_probability_record"]

    assert markov_record["probability"] == 0.75
    assert markov_record["support_unavailable_reason"] == "missing_probability_record_field"
    assert (
        evidence["unavailable_reasons"]["adaptive_learning.markov_probability_record.support"]
        == "missing_probability_record_field"
    )
    assert any(
        failure.get("model_name") == "adaptive_learning.markov_probability_record.support"
        and failure.get("failure_type") == "invalid_model_contract_record_schema"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1289-nested-compact") is True
