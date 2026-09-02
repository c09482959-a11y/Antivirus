from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1285_direct_contract_nested_model_failures_must_be_valid_records() -> None:
    record = {
        "file": "direct-contract-malformed-nested-failure.bin",
        "path": "direct-contract-malformed-nested-failure.bin",
        "classification": "suspicious",
        "score": 73.0,
        "model_feature_bundle": {
            "features": {"markov_ready": False},
            "model_failures": ["not-a-model-failure-record"],
        },
    }

    with pytest.raises(
        ValueError,
        match=r"model_feature_bundle\.model_failures\[0\].*model failure record must be an object",
    ):
        validate_evidence_object_invariants(record, context="stage1285-direct-contract")


def test_stage1285_upstream_model_evidence_contract_nested_model_failures_must_be_valid_records() -> None:
    record = {
        "file": "upstream-contract-malformed-nested-failure.bin",
        "path": "upstream-contract-malformed-nested-failure.bin",
        "classification": "suspicious",
        "score": 74.0,
        "model_evidence": {
            "temporal_overlay_record": {
                "stage_probability_ready": False,
                "model_failure": {"model_name": "temporal", "failure_type": "cold_start"},
            }
        },
    }

    with pytest.raises(
        ValueError,
        match=r"model_evidence:temporal_overlay_record\.model_failure.*missing reason",
    ):
        validate_evidence_object_invariants(record, context="stage1285-upstream-contract")


def test_stage1285_nested_model_signal_failures_validate_and_publish() -> None:
    record = {
        "file": "nested-signal-valid-failure.bin",
        "path": "nested-signal-valid-failure.bin",
        "classification": "suspicious",
        "score": 75.0,
        "adaptive_learning": {
            "bucket_vector": {
                "model_failures": [
                    {
                        "model_name": "profile",
                        "failure_type": "degraded_state",
                        "reason": "baseline_snapshot_unavailable",
                    }
                ]
            }
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1285-valid-signal") is True
    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure.get("model_name") == "profile"
        and failure.get("failure_type") == "degraded_state"
        and failure.get("reason") == "baseline_snapshot_unavailable"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1285-compact") is True
