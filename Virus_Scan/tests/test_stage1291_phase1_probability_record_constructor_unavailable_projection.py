from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
)
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1291_probability_record_constructor_does_not_clamp_out_of_bounds_probability() -> None:
    record = make_probability_record(
        ready=True,
        probability=2.0,
        support=4,
        count=4,
        vocab=1,
        smoothing="none",
        reason="trained",
        model_version="probability_record_v1",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["probability_unavailable_reason"] == "out_of_bounds_probability"
    assert record["reason"] == "trained"

    materialized = materialize_probability_record(record)
    assert materialized["probability"] is None
    assert materialized["probability_unavailable_reason"] == "out_of_bounds_probability"
    assert validate_evidence_object_invariants(
        {
            "file": "constructor-invalid-probability.exe",
            "path": "constructor-invalid-probability.exe",
            "classification": "suspicious",
            "score": 78.0,
            "probability_record": materialized,
        },
        context="stage1291-constructor-record",
    ) is True


def test_stage1291_probability_record_unavailable_reason_activates_final_json_and_replay_flags() -> None:
    compact = compact_result_record(
        {
            "file": "constructor-invalid-probability-projection.exe",
            "path": "constructor-invalid-probability-projection.exe",
            "classification": "suspicious",
            "score": 78.0,
            "tags": ["probability_constructor_signal"],
            "explanation": {"reasons": ["constructor probability record affected model evidence"]},
            "probability_record": materialize_probability_record(
                make_probability_record(
                    ready=True,
                    probability=2.0,
                    support=4,
                    count=4,
                    vocab=1,
                    smoothing="none",
                    reason="trained",
                    model_version="probability_record_v1",
                )
            ),
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert probability_record["ready"] is False
    assert probability_record["probability"] is None
    assert probability_record["probability_unavailable_reason"] == "out_of_bounds_probability"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "out_of_bounds_probability"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1291-compact") is True


def test_stage1291_blank_contract_unavailable_reason_is_boundary_invalid_and_sanitized() -> None:
    record = {
        "file": "blank-probability-unavailable-reason.exe",
        "path": "blank-probability-unavailable-reason.exe",
        "classification": "suspicious",
        "score": 72.0,
        "probability_record": {
            "ready": False,
            "probability": None,
            "probability_unavailable_reason": "",
            "support": 0,
            "count": 0,
            "vocab": 0,
            "smoothing": "none",
            "reason": "invalid_probability",
            "model_version": "probability_record_v1",
        },
    }

    with pytest.raises(ValueError, match="unavailable reason must be non-empty text"):
        validate_evidence_object_invariants(record, context="stage1291-source")

    compact = compact_result_record(record)
    evidence = compact["model_evidence"]

    assert evidence["probability_record"]["probability_unavailable_reason"] == "invalid_model_unavailable_reason"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "invalid_model_unavailable_reason"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure.get("model_name") == "probability_record.probability_unavailable_reason"
        and failure.get("failure_type") == "invalid_model_contract_record_schema"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1291-sanitized-compact") is True
