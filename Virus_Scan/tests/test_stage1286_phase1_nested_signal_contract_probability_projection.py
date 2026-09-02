from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1286_nested_signal_contract_probability_bounds_are_result_boundary_invalid() -> None:
    record = {
        "file": "nested-signal-contract-invalid.bin",
        "path": "nested-signal-contract-invalid.bin",
        "classification": "suspicious",
        "score": 75.0,
        "adaptive_learning": {
            "temporal_overlay_record": {
                "stage_probability": 2.0,
                "confidence": 0.5,
            }
        },
    }

    with pytest.raises(
        ValueError,
        match=r"adaptive_learning\.temporal_overlay_record\.stage_probability.*probability out of bounds",
    ):
        validate_evidence_object_invariants(record, context="stage1286-source")


def test_stage1286_nested_signal_contract_invalid_probability_projects_failure_evidence() -> None:
    record = {
        "file": "nested-signal-contract-invalid-projection.bin",
        "path": "nested-signal-contract-invalid-projection.bin",
        "classification": "suspicious",
        "score": 76.0,
        "adaptive_learning": {
            "temporal_overlay_record": {
                "stage_probability": 2.0,
                "confidence": 0.5,
            }
        },
    }

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]

    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["temporal_overlay_record"]["stage_probability_unavailable_reason"] == "out_of_bounds_probability"
    assert evidence["unavailable_reasons"]["adaptive_learning.temporal_overlay_record.stage_probability"] == "out_of_bounds_probability"
    assert any(
        failure.get("model_name") == "adaptive_learning.temporal_overlay_record.stage_probability"
        and failure.get("failure_type") == "invalid_model_probability"
        and failure.get("reason") == "out_of_bounds_probability"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1286-compact") is True


def test_stage1286_nested_signal_contract_valid_probability_reaches_model_evidence() -> None:
    record = {
        "file": "nested-signal-contract-valid.bin",
        "path": "nested-signal-contract-valid.bin",
        "classification": "suspicious",
        "score": 77.0,
        "adaptive_learning": {
            "temporal_overlay_record": {
                "stage_probability": 0.25,
                "confidence": 0.5,
                "probability_ready": True,
            }
        },
    }

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]

    assert evidence["temporal_overlay_record"]["stage_probability"] == 0.25
    assert evidence["temporal_overlay_record"]["confidence"] == 0.5
    assert evidence["temporal_overlay_record"]["probability_ready"] is True
    assert validate_evidence_object_invariants(compact, context="stage1286-valid-compact") is True
