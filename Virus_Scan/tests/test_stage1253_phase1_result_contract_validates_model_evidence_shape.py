from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import (
    validate_evidence_object_invariants,
    validate_result_record_invariants,
)


def test_stage1253_result_contract_rejects_non_json_model_evidence() -> None:
    record = {
        "file": "model-evidence-malformed.py",
        "path": "model-evidence-malformed.py",
        "classification": "high",
        "score": 82.0,
        "model_evidence": {
            "writer_version": "model_evidence_writer_v1",
            "final_json_must_record": True,
            "model_failures": [
                {
                    "model_name": "temporal",
                    "failure_type": "cold_start",
                    "reason": object(),
                    "output_affecting": True,
                }
            ],
        },
    }

    with pytest.raises(ValueError, match="non-json value"):
        validate_result_record_invariants(record, context="stage1253_model_evidence")


def test_stage1253_result_contract_rejects_non_json_feature_probabilities() -> None:
    record = {
        "file": "feature-probabilities-malformed.py",
        "path": "feature-probabilities-malformed.py",
        "classification": "high",
        "score": 82.0,
        "feature_probabilities": {
            "temporal": 0.0,
            "model_failure": {"model_name": "temporal", "reason": object()},
        },
    }

    with pytest.raises(ValueError, match="non-json value"):
        validate_evidence_object_invariants(record, context="stage1253_feature_probability")


def test_stage1253_result_contract_accepts_json_model_evidence_shape() -> None:
    record = {
        "file": "model-evidence-valid.py",
        "path": "model-evidence-valid.py",
        "classification": "high",
        "score": 82.0,
        "model_evidence": {
            "writer_version": "model_evidence_writer_v1",
            "final_json_must_record": True,
            "replay_record_required": True,
            "feature_probabilities": {"markov": 0.0, "temporal": 0.0},
            "unavailable_reasons": {"temporal": "missing_snapshot"},
            "model_failures": [
                {
                    "model_name": "temporal",
                    "failure_type": "cold_start",
                    "reason": "missing_snapshot",
                    "output_affecting": True,
                }
            ],
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1253_valid_model_evidence") is True
    assert validate_result_record_invariants(record, context="stage1253_valid_model_evidence") is True
