from __future__ import annotations

from Virus_Scan.contracts.result_record import (
    ResultEvidenceSnapshot,
    normalize_result_record,
    result_has_scan_evidence,
    validate_result_record_invariants,
)


def _model_evidence_only_high_record() -> dict[str, object]:
    return {
        "file": "model-evidence-only.py",
        "path": "model-evidence-only.py",
        "classification": "high",
        "score": 82.0,
        "tags": [],
        "chains": [],
        "yara_signals": [],
        "decoded_evidence_snippets": [],
        "model_evidence": {
            "writer_version": "model_evidence_writer_v1",
            "final_json_must_record": True,
            "replay_record_required": True,
            "model_failures": (
                {
                    "model_name": "temporal",
                    "failure_type": "cold_start",
                    "reason": "missing_snapshot",
                    "output_affecting": True,
                },
            ),
            "unavailable_reasons": {"temporal": "missing_snapshot"},
        },
    }


def test_stage1252_result_evidence_snapshot_counts_canonical_model_evidence() -> None:
    record = _model_evidence_only_high_record()

    snapshot = ResultEvidenceSnapshot.from_record(record)

    assert snapshot.model_evidence_count == 1
    assert snapshot.has_evidence is True
    assert validate_result_record_invariants(record, context="stage1252") is True


def test_stage1252_normalize_result_record_does_not_reclassify_model_evidence_as_scanner_failure() -> None:
    record = _model_evidence_only_high_record()

    normalized = normalize_result_record(record, source="stage1252_model_evidence_contract")

    assert result_has_scan_evidence(record) is True
    assert "result_contract_violation" not in normalized["tags"]
    assert "scanner_failure" not in normalized["tags"]
    assert normalized["classification"] == "high"
    assert normalized["model_evidence"]["final_json_must_record"] is True
