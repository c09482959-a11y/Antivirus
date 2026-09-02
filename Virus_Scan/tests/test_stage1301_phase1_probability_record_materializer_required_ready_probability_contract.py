from __future__ import annotations

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import materialize_probability_record
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1301_materializer_records_missing_ready_as_unavailable_evidence() -> None:
    materialized = materialize_probability_record(
        {
            "probability": 0.88,
            "support": 9,
            "count": 5,
            "vocab": 4,
            "smoothing": "laplace",
            "reason": "trained",
            "model_version": "stage1301_probability_record_v1",
        }
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["ready_unavailable_reason"] == "missing_probability_record_field"
    assert materialized["probability_unavailable_reason"] == "not_ready_probability_present"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1301-materialized-missing-ready",
    ) is True


def test_stage1301_materializer_records_missing_probability_as_unavailable_evidence() -> None:
    materialized = materialize_probability_record(
        {
            "ready": False,
            "support": 3,
            "count": 2,
            "vocab": 2,
            "smoothing": "laplace",
            "reason": "cold_start",
            "model_version": "stage1301_probability_record_v1",
        }
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["probability_unavailable_reason"] == "missing_probability_record_field"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1301-materialized-missing-probability",
    ) is True


def test_stage1301_materialized_missing_ready_probability_reaches_final_json_and_replay_flags() -> None:
    compact = compact_result_record(
        {
            "file": "probability-record-missing-ready-probability.exe",
            "path": "probability-record-missing-ready-probability.exe",
            "classification": "suspicious",
            "score": 77.0,
            "probability_record": materialize_probability_record(
                {
                    "support": 3,
                    "count": 2,
                    "vocab": 2,
                    "smoothing": "laplace",
                    "reason": "cold_start",
                    "model_version": "stage1301_probability_record_v1",
                }
            ),
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert probability_record["ready"] is False
    assert probability_record["probability"] is None
    assert probability_record["ready_unavailable_reason"] == "missing_probability_record_field"
    assert probability_record["probability_unavailable_reason"] == "missing_probability_record_field"
    assert evidence["unavailable_reasons"]["probability_record.ready"] == "missing_probability_record_field"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "missing_probability_record_field"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1301-compact") is True
