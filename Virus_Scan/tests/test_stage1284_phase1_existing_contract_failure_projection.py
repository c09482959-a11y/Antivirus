from __future__ import annotations

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1284_existing_model_contract_failures_activate_final_json_and_replay_flags() -> None:
    record = {
        "file": "existing-contract-failure-projection.bin",
        "path": "existing-contract-failure-projection.bin",
        "classification": "suspicious",
        "score": 71.0,
        "tags": ["existing_contract_failure_projection"],
        "model_evidence": {
            "model_feature_bundle": {
                "features": {"markov_ready": False},
                "model_failures": [
                    {
                        "model_name": "markov",
                        "failure_type": "unavailable_snapshot",
                        "reason": "runtime_markov_snapshot_missing",
                    }
                ],
            }
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1284-source") is True

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    projected = {
        (failure.get("model_name"), failure.get("failure_type"), failure.get("reason"))
        for failure in evidence["model_failures"]
    }
    assert ("markov", "unavailable_snapshot", "runtime_markov_snapshot_missing") in projected
    assert validate_evidence_object_invariants(compact, context="stage1284-compact") is True
