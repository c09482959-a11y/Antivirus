from __future__ import annotations

import math

import pytest

from Virus_Scan.contracts.result_record import (
    ResultEvidenceSnapshot,
    normalize_result_record,
    result_has_scan_evidence,
    validate_evidence_object_invariants,
)
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1259_layered_detection_counts_as_model_evidence_not_scanner_failure() -> None:
    record = {
        "file": "layered-model.exe",
        "path": "layered-model.exe",
        "classification": "suspicious",
        "score": 82.0,
        "layered_detection": {
            "score": 82.0,
            "classification": "malicious",
            "layers": {"api": {"score": 82.0, "hits": ["process_exec"]}},
            "active_layers": 1,
        },
        "layer_weights": {"api": 1.0},
    }

    assert result_has_scan_evidence(record)
    assert ResultEvidenceSnapshot.from_record(record).model_evidence_count == 2

    normalized = normalize_result_record(record, source="stage1259_test")
    assert "result_contract_violation" not in normalized.get("tags", ())
    assert "scanner_failure" not in normalized.get("tags", ())
    assert not normalized.get("error")


def test_stage1259_layered_detection_shape_is_validated_as_model_evidence() -> None:
    record = {
        "file": "layered-model.exe",
        "path": "layered-model.exe",
        "classification": "suspicious",
        "score": 82.0,
        "layered_detection": {"score": math.inf},
    }

    with pytest.raises(ValueError, match="layered_detection.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1259")


def test_stage1259_nonfinite_layered_detection_projects_explicit_model_failure() -> None:
    record = {
        "file": "layered-model.exe",
        "path": "layered-model.exe",
        "classification": "suspicious",
        "score": 82.0,
        "tags": ["layered_model_signal"],
        "explanation": {"reasons": ["layered scoring emitted invalid model value"]},
        "layered_detection": {
            "score": math.nan,
            "classification": "malicious",
            "layers": {"api": {"score": math.inf}},
        },
        "layer_weights": {"api": math.inf},
    }

    compact = compact_result_record(record)

    summary = compact["layered_detection_summary"]
    assert summary["score"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert summary["layers"]["api"]["score"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }

    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence["model_failures"]
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "layered_detection"
        for failure in failures
    )
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "layer_weights"
        for failure in failures
    )
