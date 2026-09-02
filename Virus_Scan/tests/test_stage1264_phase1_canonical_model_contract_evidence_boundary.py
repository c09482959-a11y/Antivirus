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


def test_stage1264_root_model_failures_count_as_model_evidence_not_scanner_failure() -> None:
    record = {
        "file": "model-failure-only.exe",
        "path": "model-failure-only.exe",
        "classification": "suspicious",
        "score": 91.0,
        "model_failures": [
            {
                "model_name": "temporal",
                "failure_type": "cold_start",
                "reason": "insufficient_temporal_history",
                "output_affecting": True,
            }
        ],
    }

    assert result_has_scan_evidence(record)
    snapshot = ResultEvidenceSnapshot.from_record(record)
    assert snapshot.model_evidence_count == 1

    normalized = normalize_result_record(record, source="stage1264_test")
    assert "result_contract_violation" not in normalized.get("tags", ())
    assert "scanner_failure" not in normalized.get("tags", ())
    assert not normalized.get("error")


def test_stage1264_canonical_model_contract_shapes_are_validated() -> None:
    record = {
        "file": "model-contract.exe",
        "path": "model-contract.exe",
        "classification": "suspicious",
        "score": 83.0,
        "model_feature_bundle": {"markov": {"probability": math.inf}},
    }

    with pytest.raises(ValueError, match="model_feature_bundle.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1264")

    record.pop("model_feature_bundle")
    record["probability_record"] = {"ready": True, "probability": math.nan}
    with pytest.raises(ValueError, match="probability_record.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1264")


def test_stage1264_direct_model_contract_records_are_final_json_visible() -> None:
    compact = compact_result_record(
        {
            "file": "model-contract.exe",
            "path": "model-contract.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["canonical_model_contract_signal"],
            "explanation": {"reasons": ["canonical model contract output affected scoring"]},
            "model_failure": {
                "model_name": "markov",
                "failure_type": "cold_start",
                "reason": "insufficient_markov_support",
                "output_affecting": True,
            },
            "model_feature_bundle": {
                "markov": {"ready": False, "reason": "insufficient_markov_support"},
                "temporal": {"ready": False},
                "model_version": "model_feature_bundle_v1",
            },
            "probability_record": {
                "ready": False,
                "probability": None,
                "support": 0,
                "count": 0,
                "vocab": 0,
                "reason": "cold_start",
                "smoothing": "none",
                "model_version": "probability_record_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_feature_bundle"]["markov"]["reason"] == "insufficient_markov_support"
    assert evidence["probability_record"]["reason"] == "cold_start"
    assert any(
        failure["failure_type"] == "cold_start"
        and failure["model_name"] == "markov"
        for failure in evidence["model_failures"]
    )
    assert compact["model_feature_bundle_summary"]["markov"]["ready"] is False
