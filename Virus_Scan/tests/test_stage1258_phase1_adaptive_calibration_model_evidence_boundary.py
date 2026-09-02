import math

import pytest

from Virus_Scan.contracts.result_record import (
    ResultEvidenceSnapshot,
    normalize_result_record,
    result_has_scan_evidence,
    validate_evidence_object_invariants,
)
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1258_adaptive_calibration_counts_as_model_evidence_not_scanner_failure():
    record = {
        "file": "sample.exe",
        "path": "sample.exe",
        "classification": "suspicious",
        "score": 80.0,
        "analytical_calibration": {
            "evidence_type": "analytical_calibration_bundle",
            "calibrated_probability": 0.91,
        },
    }

    assert result_has_scan_evidence(record)
    assert ResultEvidenceSnapshot.from_record(record).model_evidence_count == 1

    normalized = normalize_result_record(record, source="stage1258_test")
    assert "result_contract_violation" not in normalized.get("tags", ())
    assert "scanner_failure" not in normalized.get("tags", ())
    assert not normalized.get("error")


def test_stage1258_adaptive_calibration_shape_is_validated_as_model_evidence():
    record = {
        "file": "sample.exe",
        "path": "sample.exe",
        "classification": "suspicious",
        "score": 80.0,
        "analytical_calibration": {"calibrated_probability": math.inf},
    }

    with pytest.raises(ValueError, match="analytical_calibration.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1258")


def test_stage1258_nonfinite_adaptive_calibration_projects_explicit_model_failure():
    record = {
        "file": "sample.exe",
        "path": "sample.exe",
        "classification": "suspicious",
        "score": 80.0,
        "tags": ["adaptive_model_signal"],
        "explanation": {"reasons": ["adaptive calibration emitted invalid probability"]},
        "analytical_calibration": {
            "evidence_type": "analytical_calibration_bundle",
            "calibrated_probability": math.nan,
            "confidence": math.inf,
        },
    }

    compact = compact_result_record(record)

    summary = compact["analytical_calibration_summary"]
    assert summary["calibrated_probability"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence["model_failures"]
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "analytical_calibration"
        for failure in failures
    )
