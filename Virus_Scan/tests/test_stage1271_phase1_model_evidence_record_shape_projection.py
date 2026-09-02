from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1271_non_mapping_model_evidence_is_result_boundary_invalid() -> None:
    record = {
        "file": "invalid-model-evidence.exe",
        "path": "invalid-model-evidence.exe",
        "classification": "suspicious",
        "score": 84.0,
        "model_evidence": "not-a-model-evidence-record",
    }

    with pytest.raises(ValueError, match=r"model_evidence.*model evidence record must be an object"):
        validate_evidence_object_invariants(record, context="stage1271")


def test_stage1271_non_mapping_model_evidence_becomes_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "invalid-model-evidence.exe",
            "path": "invalid-model-evidence.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["model_evidence_signal"],
            "explanation": {"reasons": ["model evidence affected final JSON visibility"]},
            "model_evidence": "not-a-model-evidence-record",
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["unavailable_reasons"]["model_evidence"] == "non_mapping_model_evidence_record"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_failures"] == (
        {
            "model_name": "model_evidence",
            "failure_type": "invalid_model_evidence_record",
            "reason": "non_mapping_model_evidence_record",
            "affected_fields": ("model_evidence",),
            "model_version": "model_evidence_writer_v1",
            "details": {
                "source_field": "model_evidence",
                "value_type": "str",
                "value_repr": "'not-a-model-evidence-record'",
            },
        },
    )


def test_stage1271_empty_model_evidence_remains_absent_without_fake_failure() -> None:
    compact = compact_result_record(
        {
            "file": "empty-model-evidence.exe",
            "path": "empty-model-evidence.exe",
            "classification": "clean",
            "score": 0.0,
            "model_evidence": "",
        }
    )

    assert "model_evidence" not in compact
