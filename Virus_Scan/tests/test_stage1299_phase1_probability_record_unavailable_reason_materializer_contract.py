from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import materialize_probability_record
from Virus_Scan.publication.json_writer import compact_result_record


def _probability_record(**overrides):
    record = {
        "ready": True,
        "probability": 0.81,
        "support": 11,
        "count": 8,
        "vocab": 5,
        "smoothing": "laplace",
        "reason": "trained",
        "model_version": "stage1299_probability_record_v1",
    }
    record.update(overrides)
    return record


def test_stage1299_result_contract_rejects_non_text_unavailable_reason() -> None:
    with pytest.raises(ValueError, match="unavailable reason must be non-empty text"):
        validate_evidence_object_invariants(
            {
                "probability_record": _probability_record(
                    support_unavailable_reason={"bad": "reason"},
                )
            },
            context="stage1299-non-text-unavailable-reason",
        )


def test_stage1299_materializer_degrades_non_text_unavailable_reason_without_repr_leak() -> None:
    materialized = materialize_probability_record(
        _probability_record(support_unavailable_reason={"bad": "reason"})
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["support_unavailable_reason"] == "invalid_unavailable_reason"
    assert materialized["probability_unavailable_reason"] == "non_text_unavailable_reason"
    assert "bad" not in materialized["support_unavailable_reason"]
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1299-materialized-non-text-unavailable-reason",
    ) is True


def test_stage1299_materializer_degrades_blank_unavailable_reason_without_learned_probability() -> None:
    materialized = materialize_probability_record(
        _probability_record(count_unavailable_reason="  ")
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["count_unavailable_reason"] == "invalid_unavailable_reason"
    assert materialized["probability_unavailable_reason"] == "blank_unavailable_reason"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1299-materialized-blank-unavailable-reason",
    ) is True


def test_stage1299_publication_records_materialized_unavailable_reason_degradation() -> None:
    materialized = materialize_probability_record(
        _probability_record(support_unavailable_reason={"bad": "reason"})
    )
    compact = compact_result_record(
        {
            "file": "probability-record-invalid-unavailable-reason.exe",
            "path": "probability-record-invalid-unavailable-reason.exe",
            "classification": "suspicious",
            "score": 73.0,
            "probability_record": materialized,
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert probability_record["ready"] is False
    assert probability_record["probability"] is None
    assert probability_record["support_unavailable_reason"] == "invalid_unavailable_reason"
    assert probability_record["probability_unavailable_reason"] == "non_text_unavailable_reason"
    assert evidence["unavailable_reasons"]["probability_record.support"] == "invalid_unavailable_reason"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "non_text_unavailable_reason"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1299-compact") is True
