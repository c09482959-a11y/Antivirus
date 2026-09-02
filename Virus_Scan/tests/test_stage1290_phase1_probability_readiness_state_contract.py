from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1290_direct_probability_record_ready_true_requires_probability() -> None:
    record = {
        "file": "ready-true-missing-probability.exe",
        "path": "ready-true-missing-probability.exe",
        "classification": "suspicious",
        "score": 78.0,
        "probability_record": {
            "ready": True,
            "probability": None,
            "support": 3,
            "count": 1,
            "vocab": 2,
            "smoothing": "none",
            "reason": None,
            "model_version": "probability_record_v1",
        },
    }

    with pytest.raises(ValueError, match=r"ready probability record missing probability"):
        validate_evidence_object_invariants(record, context="stage1290-source")


def test_stage1290_direct_probability_record_ready_true_missing_probability_projects_degraded_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "ready-true-missing-probability-projection.exe",
            "path": "ready-true-missing-probability-projection.exe",
            "classification": "suspicious",
            "score": 78.0,
            "tags": ["probability_ready_state_signal"],
            "explanation": {"reasons": ["probability readiness state affected model evidence"]},
            "probability_record": {
                "ready": True,
                "probability": None,
                "support": 3,
                "count": 1,
                "vocab": 2,
                "smoothing": "none",
                "reason": None,
                "model_version": "probability_record_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert "ready" not in probability_record
    assert "probability" not in probability_record
    assert probability_record["ready_unavailable_reason"] == "ready_probability_missing"
    assert probability_record["probability_unavailable_reason"] == "ready_probability_missing"
    assert evidence["unavailable_reasons"]["probability_record.ready"] == "ready_probability_missing"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "ready_probability_missing"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure.get("model_name") == "probability_record.probability"
        and failure.get("failure_type") == "invalid_model_contract_record_schema"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1290-compact") is True


def test_stage1290_nested_markov_probability_record_not_ready_cannot_publish_probability() -> None:
    record = {
        "file": "nested-not-ready-has-probability.bin",
        "path": "nested-not-ready-has-probability.bin",
        "classification": "suspicious",
        "score": 79.0,
        "adaptive_learning": {
            "markov_probability_record": {
                "ready": False,
                "probability": 0.9,
                "support": 0,
                "count": 0,
                "vocab": 0,
                "smoothing": "none",
                "reason": "insufficient_markov_support",
                "model_version": "markov_probability_v1",
            }
        },
    }

    with pytest.raises(ValueError, match=r"not-ready probability record cannot carry probability"):
        validate_evidence_object_invariants(record, context="stage1290-nested-source")

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    markov_record = evidence["markov_probability_record"]

    assert markov_record["ready"] is False
    assert "probability" not in markov_record
    assert markov_record["probability_unavailable_reason"] == "not_ready_probability_present"
    assert (
        evidence["unavailable_reasons"]["adaptive_learning.markov_probability_record.probability"]
        == "not_ready_probability_present"
    )
    assert any(
        failure.get("model_name") == "adaptive_learning.markov_probability_record.probability"
        and failure.get("failure_type") == "invalid_model_contract_record_schema"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1290-nested-compact") is True


def test_stage1290_not_ready_probability_record_requires_reason() -> None:
    record = {
        "file": "not-ready-missing-reason.exe",
        "path": "not-ready-missing-reason.exe",
        "classification": "suspicious",
        "score": 76.0,
        "probability_record": {
            "ready": False,
            "probability": None,
            "support": 0,
            "count": 0,
            "vocab": 0,
            "smoothing": "none",
            "reason": None,
            "model_version": "probability_record_v1",
        },
    }

    with pytest.raises(ValueError, match=r"not-ready probability record missing reason"):
        validate_evidence_object_invariants(record, context="stage1290-missing-reason-source")

    compact = compact_result_record(record)
    probability_record = compact["model_evidence"]["probability_record"]
    assert probability_record["reason_unavailable_reason"] == "not_ready_reason_missing"
    assert (
        compact["model_evidence"]["unavailable_reasons"]["probability_record.reason"]
        == "not_ready_reason_missing"
    )
    assert validate_evidence_object_invariants(compact, context="stage1290-missing-reason-compact") is True
