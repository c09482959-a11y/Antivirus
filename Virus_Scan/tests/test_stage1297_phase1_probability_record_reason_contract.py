from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
)
from Virus_Scan.publication.json_writer import compact_result_record


def _probability_record(**overrides):
    record = {
        "ready": True,
        "probability": 0.64,
        "support": 7,
        "count": 5,
        "vocab": 3,
        "smoothing": "laplace",
        "reason": "trained",
        "model_version": "stage1297_probability_record_v1",
    }
    record.update(overrides)
    return record


def test_stage1297_result_contract_rejects_non_text_probability_record_reason() -> None:
    with pytest.raises(ValueError, match="reason must be non-empty text or null"):
        validate_evidence_object_invariants(
            {"probability_record": _probability_record(reason={"why": "bad"})},
            context="stage1297-non-text-reason",
        )


def test_stage1297_constructor_degrades_invalid_reason_without_learned_probability() -> None:
    record = make_probability_record(
        ready=True,
        probability=0.64,
        support=7,
        count=5,
        vocab=3,
        smoothing="laplace",
        reason={"why": "bad"},
        model_version="stage1297_probability_record_v1",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "non_text_reason"
    assert record["reason_unavailable_reason"] == "non_text_reason"
    assert record["probability_unavailable_reason"] == "non_text_reason"
    assert validate_evidence_object_invariants(
        {"probability_record": record},
        context="stage1297-constructor-invalid-reason",
    ) is True


def test_stage1297_materializer_degrades_invalid_reason_without_learned_probability() -> None:
    materialized = materialize_probability_record(
        _probability_record(reason=["bad", "reason"]),
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["reason"] == "non_text_reason"
    assert materialized["reason_unavailable_reason"] == "non_text_reason"
    assert materialized["probability_unavailable_reason"] == "non_text_reason"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1297-materializer-invalid-reason",
    ) is True


def test_stage1297_publication_projects_invalid_reason_as_degraded_model_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "probability-record-invalid-reason.exe",
            "path": "probability-record-invalid-reason.exe",
            "classification": "suspicious",
            "score": 73.0,
            "probability_record": _probability_record(reason={"why": "bad"}),
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert "reason" not in probability_record
    assert probability_record["reason_unavailable_reason"] == "non_text_probability_record_field"
    assert evidence["unavailable_reasons"]["probability_record.reason"] == "non_text_probability_record_field"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["model_name"] == "probability_record.reason"
        and failure["reason"] == "non_text_probability_record_field"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1297-compact") is True
