from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1288_direct_probability_record_string_ready_is_boundary_invalid() -> None:
    record = {
        "file": "bad-ready.exe",
        "path": "bad-ready.exe",
        "classification": "suspicious",
        "score": 75.0,
        "probability_record": {
            "ready": "yes",
            "probability": 0.5,
            "support": 1,
            "count": 1,
            "vocab": 2,
            "reason": "trained",
            "smoothing": "none",
            "model_version": "probability_record_v1",
        },
    }

    with pytest.raises(ValueError, match=r"probability_record\.ready.*readiness flag"):
        validate_evidence_object_invariants(record, context="stage1288-source")


def test_stage1288_direct_probability_record_invalid_ready_projects_degraded_model_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "bad-ready-projection.exe",
            "path": "bad-ready-projection.exe",
            "classification": "suspicious",
            "score": 76.0,
            "tags": ["probability_record_ready_signal"],
            "explanation": {"reasons": ["probability readiness affected model evidence"]},
            "probability_record": {
                "ready": "yes",
                "probability": 0.5,
                "support": 1,
                "count": 1,
                "vocab": 2,
                "reason": "trained",
                "smoothing": "none",
                "model_version": "probability_record_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert "ready" not in probability_record
    assert probability_record["ready_unavailable_reason"] == "non_boolean_readiness_flag"
    assert evidence["unavailable_reasons"]["probability_record.ready"] == "non_boolean_readiness_flag"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure.get("failure_type") == "invalid_model_readiness_flag"
        and failure.get("model_name") == "probability_record.ready"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1288-compact") is True


def test_stage1288_nested_temporal_probability_ready_is_validated_and_projected() -> None:
    record = {
        "file": "nested-bad-ready.bin",
        "path": "nested-bad-ready.bin",
        "classification": "suspicious",
        "score": 77.0,
        "adaptive_learning": {
            "temporal_overlay_record": {
                "probability_ready": "true",
                "stage_probability": 0.25,
                "stage_probability_support": 1,
                "confidence": 0.5,
            }
        },
    }

    with pytest.raises(ValueError, match=r"probability_ready.*readiness flag"):
        validate_evidence_object_invariants(record, context="stage1288-nested-source")

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    temporal_record = evidence["temporal_overlay_record"]

    assert temporal_record["stage_probability"] == 0.25
    assert "probability_ready" not in temporal_record
    assert temporal_record["probability_ready_unavailable_reason"] == "non_boolean_readiness_flag"
    assert (
        evidence["unavailable_reasons"]["adaptive_learning.temporal_overlay_record.probability_ready"]
        == "non_boolean_readiness_flag"
    )
    assert any(
        failure.get("model_name") == "adaptive_learning.temporal_overlay_record.probability_ready"
        and failure.get("failure_type") == "invalid_model_readiness_flag"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1288-nested-compact") is True


def test_stage1288_valid_false_ready_flags_are_preserved() -> None:
    compact = compact_result_record(
        {
            "file": "valid-false-ready.exe",
            "path": "valid-false-ready.exe",
            "classification": "suspicious",
            "score": 70.0,
            "probability_record": {
                "ready": False,
                "probability": None,
                "support": 0,
                "count": 0,
                "vocab": 0,
                "reason": "insufficient_support",
                "smoothing": "none",
                "model_version": "probability_record_v1",
            },
            "adaptive_learning": {
                "temporal_overlay_record": {
                    "probability_ready": False,
                    "stage_probability": None,
                    "stage_probability_support": 0,
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["probability_record"]["ready"] is False
    assert evidence["temporal_overlay_record"]["probability_ready"] is False
    assert not evidence.get("model_failures")
    assert validate_evidence_object_invariants(compact, context="stage1288-valid-compact") is True
