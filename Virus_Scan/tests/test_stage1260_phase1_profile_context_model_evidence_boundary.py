from __future__ import annotations

import math

import pytest

from Virus_Scan.contracts.result_record import (
    ResultEvidenceSnapshot,
    normalize_result_record,
    result_has_scan_evidence,
    validate_evidence_object_invariants,
)
from Virus_Scan.publication import json_writer
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1260_profile_context_counts_as_model_evidence_not_scanner_failure() -> None:
    record = {
        "file": "profile-model.exe",
        "path": "profile-model.exe",
        "classification": "suspicious",
        "score": 83.0,
        "profile_selection": {"active_profile": "renpy"},
        "detection_profile_context": {
            "active_profile": "renpy",
            "selection_reasons": ("selected_from_engine_context",),
        },
        "engine_context": {"renpy": 0.91, "other": 0.09},
        "engine_confidence": {"active_profile": "renpy", "confidence": 0.91},
        "feature_vector": [1.0, 0.91, 0.09],
    }

    assert result_has_scan_evidence(record)
    assert ResultEvidenceSnapshot.from_record(record).model_evidence_count >= 5

    normalized = normalize_result_record(record, source="stage1260_test")
    assert "result_contract_violation" not in normalized.get("tags", ())
    assert "scanner_failure" not in normalized.get("tags", ())
    assert not normalized.get("error")


def test_stage1260_profile_context_shape_is_validated_as_model_evidence() -> None:
    record = {
        "file": "profile-model.exe",
        "path": "profile-model.exe",
        "classification": "suspicious",
        "score": 83.0,
        "engine_confidence": {"active_profile": "renpy", "confidence": math.inf},
        "feature_vector": [1.0, math.nan],
    }

    with pytest.raises(ValueError, match="engine_confidence.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1260")

    record.pop("engine_confidence")
    with pytest.raises(ValueError, match="feature_vector.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1260")


def test_stage1260_compact_error_preserves_profile_context_and_projects_failure() -> None:
    record = json_writer.normalize_compact_result_record(
        {
            "file": "profile-model.exe",
            "path": "profile-model.exe",
            "classification": "suspicious",
            "score": 83.0,
            "tags": ["profile_model_signal"],
            "explanation": {"reasons": ["profile context emitted invalid model value"]},
            "profile_selection": {"active_profile": "renpy"},
            "detection_profile_context": {
                "active_profile": "renpy",
                "engine_confidence": {"confidence": math.inf},
            },
            "engine_context": {"renpy": math.nan},
            "engine_confidence": {"active_profile": "renpy", "confidence": math.inf},
            "feature_vector": [1.0, math.nan],
        }
    )

    compact = json_writer.build_compact_error_record(record, RuntimeError("forced compact failure"))

    assert compact["profile_selection"]["active_profile"] == "renpy"
    assert compact["profile_selection_summary"]["active_profile"] == "renpy"
    assert compact["engine_context_summary"]["renpy"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["engine_confidence_summary"]["confidence"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["feature_vector_summary"][1] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }

    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence["model_failures"]
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "engine_context"
        for failure in failures
    )
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "feature_vector"
        for failure in failures
    )


def test_stage1260_success_compact_records_profile_context_summary() -> None:
    compact = compact_result_record(
        {
            "file": "profile-model.exe",
            "path": "profile-model.exe",
            "classification": "suspicious",
            "score": 83.0,
            "tags": ["profile_model_signal"],
            "explanation": {"reasons": ["profile context selected renpy"]},
            "profile_selection": {"active_profile": "renpy"},
            "detection_profile_context": {"active_profile": "renpy"},
            "engine_context": {"renpy": 0.91, "other": 0.09},
            "engine_confidence": {"active_profile": "renpy", "confidence": 0.91},
            "feature_vector": [1.0, 0.91, 0.09],
        }
    )

    assert compact["profile_selection"]["active_profile"] == "renpy"
    assert compact["profile_selection_summary"]["active_profile"] == "renpy"
    assert compact["detection_profile_context_summary"]["active_profile"] == "renpy"
    assert compact["engine_context_summary"] == {"other": 0.09, "renpy": 0.91}
    assert compact["feature_vector_summary"] == [1.0, 0.91, 0.09]
