from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1267_direct_temporal_overlay_metric_bounds_are_result_boundary_invalid() -> None:
    record = {
        "file": "direct-temporal-overlay.exe",
        "path": "direct-temporal-overlay.exe",
        "classification": "suspicious",
        "score": 88.0,
        "temporal_overlay_record": {
            "ready": True,
            "stage_probability": 1.5,
            "sequence_probability": 0.5,
            "confidence": 0.6,
            "pair_probabilities": {"stage_a->stage_b": 0.4},
        },
    }

    with pytest.raises(ValueError, match=r"temporal_overlay_record\.stage_probability.*out of bounds"):
        validate_evidence_object_invariants(record, context="stage1267")

    record["temporal_overlay_record"]["stage_probability"] = 0.7
    record["temporal_overlay_record"]["pair_probabilities"]["stage_b->stage_c"] = 1.2
    with pytest.raises(ValueError, match=r"pair_probabilities\.stage_b->stage_c.*out of bounds"):
        validate_evidence_object_invariants(record, context="stage1267")


def test_stage1267_direct_temporal_overlay_invalid_metrics_become_model_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "direct-temporal-overlay.exe",
            "path": "direct-temporal-overlay.exe",
            "classification": "suspicious",
            "score": 88.0,
            "tags": ["temporal_overlay_model_signal"],
            "explanation": {"reasons": ["direct temporal overlay affected model evidence"]},
            "temporal_overlay_record": {
                "ready": True,
                "stage_probability": 1.5,
                "sequence_probability": 0.5,
                "confidence": 2.0,
                "pair_probabilities": {
                    "stage_a->stage_b": 1.2,
                    "stage_b->stage_c": 0.3,
                },
                "model_version": "temporal_overlay_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    overlay = evidence["temporal_overlay_record"]
    assert "stage_probability" not in overlay
    assert overlay["stage_probability_unavailable_reason"] == "out_of_bounds_probability"
    assert "confidence" not in overlay
    assert overlay["confidence_unavailable_reason"] == "out_of_bounds_probability"
    assert overlay["pair_probabilities"] == {"stage_b->stage_c": 0.3}
    assert overlay["pair_probabilities_unavailable_reasons"] == {"stage_a->stage_b": "out_of_bounds_probability"}
    assert evidence["unavailable_reasons"]["temporal_overlay_record.stage_probability"] == "out_of_bounds_probability"
    assert evidence["unavailable_reasons"]["temporal_overlay_record.confidence"] == "out_of_bounds_probability"
    assert evidence["unavailable_reasons"]["temporal_overlay_record.pair_probabilities.stage_a->stage_b"] == "out_of_bounds_probability"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "temporal_overlay_record.stage_probability"
        and failure["affected_fields"] == ("temporal_overlay_record", "stage_probability")
        for failure in evidence["model_failures"]
    )
    assert compact["temporal_overlay_record_summary"]["stage_probability"] == {
        "model_signal_projection_failed": True,
        "reason": "out_of_bounds_probability",
    }
    assert compact["temporal_overlay_record_summary"]["pair_probabilities"]["stage_a->stage_b"] == {
        "model_signal_projection_failed": True,
        "reason": "out_of_bounds_probability",
    }


def test_stage1267_upstream_model_evidence_contract_metrics_are_sanitized() -> None:
    compact = compact_result_record(
        {
            "file": "upstream-temporal-overlay.exe",
            "path": "upstream-temporal-overlay.exe",
            "classification": "suspicious",
            "score": 82.0,
            "tags": ["upstream_model_evidence"],
            "explanation": {"reasons": ["upstream model evidence must be replay-visible"]},
            "model_evidence": {
                "temporal_overlay_record": {
                    "ready": True,
                    "stage_probability": 1.5,
                    "sequence_probability": 0.25,
                    "confidence": 0.4,
                    "pair_probabilities": {"a->b": 0.6},
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    overlay = evidence["temporal_overlay_record"]
    assert "stage_probability" not in overlay
    assert overlay["stage_probability_unavailable_reason"] == "out_of_bounds_probability"
    assert overlay["sequence_probability"] == 0.25
    assert overlay["confidence"] == 0.4
    assert evidence["unavailable_reasons"]["temporal_overlay_record.stage_probability"] == "out_of_bounds_probability"
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "temporal_overlay_record.stage_probability"
        for failure in evidence["model_failures"]
    )
