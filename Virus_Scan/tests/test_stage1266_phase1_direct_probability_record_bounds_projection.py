from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1266_direct_probability_record_out_of_bounds_is_result_boundary_invalid() -> None:
    record = {
        "file": "direct-probability.exe",
        "path": "direct-probability.exe",
        "classification": "suspicious",
        "score": 86.0,
        "probability_record": {
            "ready": True,
            "probability": 1.5,
            "support": 12,
            "count": 9,
            "vocab": 4,
            "reason": "trained",
            "smoothing": "none",
            "model_version": "probability_record_v1",
        },
    }

    with pytest.raises(ValueError, match=r"probability_record\.probability.*out of bounds"):
        validate_evidence_object_invariants(record, context="stage1266")


def test_stage1266_direct_probability_record_invalid_probability_becomes_model_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "direct-probability.exe",
            "path": "direct-probability.exe",
            "classification": "suspicious",
            "score": 86.0,
            "tags": ["probability_contract_signal"],
            "explanation": {"reasons": ["direct probability record affected model evidence"]},
            "probability_record": {
                "ready": True,
                "probability": 1.5,
                "support": 12,
                "count": 9,
                "vocab": 4,
                "reason": "trained",
                "smoothing": "none",
                "model_version": "probability_record_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["probability_record"]["probability_unavailable_reason"] == "out_of_bounds_probability"
    assert "probability" not in evidence["probability_record"]
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "out_of_bounds_probability"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "probability_record.probability"
        and failure["affected_fields"] == ("probability_record", "probability")
        for failure in evidence["model_failures"]
    )
    assert compact["probability_record_summary"]["probability"]["reason"] == "out_of_bounds_probability"


def test_stage1266_direct_probability_record_valid_probability_is_preserved() -> None:
    compact = compact_result_record(
        {
            "file": "direct-probability-valid.exe",
            "path": "direct-probability-valid.exe",
            "classification": "suspicious",
            "score": 71.0,
            "tags": ["probability_contract_signal"],
            "explanation": {"reasons": ["direct probability record affected model evidence"]},
            "probability_record": {
                "ready": True,
                "probability": 0.25,
                "support": 12,
                "count": 3,
                "vocab": 4,
                "reason": "trained",
                "smoothing": "none",
                "model_version": "probability_record_v1",
            },
        }
    )

    assert compact["model_evidence"]["probability_record"]["probability"] == 0.25
    assert compact["probability_record_summary"]["probability"] == 0.25
    assert not compact["model_evidence"].get("model_failures")
