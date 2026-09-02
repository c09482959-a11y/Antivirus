from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1269_direct_model_contract_record_type_is_result_boundary_invalid() -> None:
    record = {
        "file": "direct-invalid-temporal-contract.exe",
        "path": "direct-invalid-temporal-contract.exe",
        "classification": "suspicious",
        "score": 84.0,
        "temporal_overlay_record": "not-a-model-contract-record",
    }

    with pytest.raises(ValueError, match=r"temporal_overlay_record.*model contract record must be an object"):
        validate_evidence_object_invariants(record, context="stage1269")


def test_stage1269_direct_non_mapping_model_contract_becomes_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "direct-invalid-temporal-contract.exe",
            "path": "direct-invalid-temporal-contract.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["temporal_overlay_model_signal"],
            "explanation": {"reasons": ["temporal overlay contract affected model evidence"]},
            "temporal_overlay_record": ["not", "a", "contract"],
        }
    )

    evidence = compact["model_evidence"]
    assert "temporal_overlay_record" not in evidence
    assert "temporal_overlay_record_summary" not in compact
    assert evidence["unavailable_reasons"]["temporal_overlay_record"] == "non_mapping_model_contract_record"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "temporal_overlay_record"
        and failure["affected_fields"] == ("temporal_overlay_record",)
        and failure["reason"] == "non_mapping_model_contract_record"
        for failure in evidence["model_failures"]
    )


def test_stage1269_upstream_non_mapping_model_contract_is_sanitized() -> None:
    compact = compact_result_record(
        {
            "file": "upstream-invalid-temporal-contract.exe",
            "path": "upstream-invalid-temporal-contract.exe",
            "classification": "suspicious",
            "score": 79.0,
            "tags": ["upstream_temporal_overlay_model_signal"],
            "explanation": {"reasons": ["upstream temporal overlay contract affected model evidence"]},
            "model_evidence": {
                "temporal_overlay_record": "not-a-contract-record",
                "writer_version": "upstream_writer_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert "temporal_overlay_record" not in evidence
    assert evidence["writer_version"] == "upstream_writer_v1"
    assert evidence["unavailable_reasons"]["temporal_overlay_record"] == "non_mapping_model_contract_record"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "temporal_overlay_record"
        and failure["affected_fields"] == ("temporal_overlay_record",)
        and failure["reason"] == "non_mapping_model_contract_record"
        for failure in evidence["model_failures"]
    )
