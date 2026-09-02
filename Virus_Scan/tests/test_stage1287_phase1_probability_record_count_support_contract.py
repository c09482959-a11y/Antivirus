from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1287_direct_probability_record_negative_count_support_is_boundary_invalid() -> None:
    record = {
        "file": "negative-support.exe",
        "path": "negative-support.exe",
        "classification": "suspicious",
        "score": 75.0,
        "probability_record": {
            "ready": True,
            "probability": 0.5,
            "support": -2,
            "count": 3,
            "vocab": 4,
            "reason": "trained",
            "smoothing": "none",
            "model_version": "probability_record_v1",
        },
    }

    with pytest.raises(ValueError, match=r"probability_record\.support.*non-negative"):
        validate_evidence_object_invariants(record, context="stage1287-source")


def test_stage1287_direct_probability_record_negative_counts_project_degraded_model_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "negative-counts.exe",
            "path": "negative-counts.exe",
            "classification": "suspicious",
            "score": 76.0,
            "tags": ["probability_record_count_signal"],
            "explanation": {"reasons": ["probability record support affected model evidence"]},
            "probability_record": {
                "ready": True,
                "probability": 0.5,
                "support": -2,
                "count": -1,
                "vocab": -3,
                "reason": "trained",
                "smoothing": "none",
                "model_version": "probability_record_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert "support" not in probability_record
    assert "count" not in probability_record
    assert "vocab" not in probability_record
    assert probability_record["support_unavailable_reason"] == "negative_count_support_metric"
    assert probability_record["count_unavailable_reason"] == "negative_count_support_metric"
    assert probability_record["vocab_unavailable_reason"] == "negative_count_support_metric"
    assert evidence["unavailable_reasons"]["probability_record.support"] == "negative_count_support_metric"
    assert evidence["unavailable_reasons"]["probability_record.count"] == "negative_count_support_metric"
    assert evidence["unavailable_reasons"]["probability_record.vocab"] == "negative_count_support_metric"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure.get("failure_type") == "invalid_model_count_support_metric"
        and failure.get("model_name") == "probability_record.support"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1287-compact") is True


def test_stage1287_nested_temporal_support_metric_is_validated_and_projected() -> None:
    record = {
        "file": "nested-negative-support.bin",
        "path": "nested-negative-support.bin",
        "classification": "suspicious",
        "score": 77.0,
        "adaptive_learning": {
            "temporal_overlay_record": {
                "stage_probability": 0.25,
                "stage_probability_support": -1,
                "confidence": 0.5,
            }
        },
    }

    with pytest.raises(ValueError, match=r"stage_probability_support.*non-negative"):
        validate_evidence_object_invariants(record, context="stage1287-nested-source")

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    temporal_record = evidence["temporal_overlay_record"]

    assert temporal_record["stage_probability"] == 0.25
    assert temporal_record["stage_probability_support_unavailable_reason"] == "negative_count_support_metric"
    assert evidence["unavailable_reasons"]["adaptive_learning.temporal_overlay_record.stage_probability_support"] == "negative_count_support_metric"
    assert any(
        failure.get("model_name") == "adaptive_learning.temporal_overlay_record.stage_probability_support"
        and failure.get("failure_type") == "invalid_model_count_support_metric"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1287-nested-compact") is True


def test_stage1287_valid_zero_count_support_metrics_are_preserved() -> None:
    compact = compact_result_record(
        {
            "file": "valid-zero-support.exe",
            "path": "valid-zero-support.exe",
            "classification": "suspicious",
            "score": 70.0,
            "tags": ["probability_record_count_signal"],
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
        }
    )

    probability_record = compact["model_evidence"]["probability_record"]
    assert probability_record["support"] == 0
    assert probability_record["count"] == 0
    assert probability_record["vocab"] == 0
    assert not compact["model_evidence"].get("model_failures")
    assert validate_evidence_object_invariants(compact, context="stage1287-valid-compact") is True
