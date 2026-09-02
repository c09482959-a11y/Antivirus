from __future__ import annotations

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import materialize_probability_record
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1293_materializer_does_not_coerce_non_boolean_ready_into_learned_probability() -> None:
    materialized = materialize_probability_record(
        {
            "ready": "yes",
            "probability": 0.91,
            "support": 8,
            "count": 7,
            "vocab": 3,
            "smoothing": "laplace",
            "reason": None,
            "model_version": "probability_record_v1",
        }
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["ready_unavailable_reason"] == "non_boolean_ready_flag"
    assert materialized["probability_unavailable_reason"] == "not_ready_probability_present"
    assert materialized["reason"] == "not_ready_probability_present"
    assert validate_evidence_object_invariants(
        {
            "file": "materialized-non-boolean-ready.exe",
            "path": "materialized-non-boolean-ready.exe",
            "classification": "suspicious",
            "score": 73.0,
            "probability_record": materialized,
        },
        context="stage1293-non-boolean-ready-materialized",
    ) is True


def test_stage1293_materializer_downgrades_invalid_raw_metrics_instead_of_silent_none() -> None:
    materialized = materialize_probability_record(
        {
            "ready": True,
            "probability": 0.62,
            "support": -1,
            "count": "many",
            "vocab": 1.25,
            "smoothing": "laplace",
            "reason": "trained",
            "model_version": "probability_record_v1",
        }
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["support"] is None
    assert materialized["count"] is None
    assert materialized["vocab"] is None
    assert materialized["support_unavailable_reason"] == "negative_support_metric"
    assert materialized["count_unavailable_reason"] == "non_numeric_count_metric"
    assert materialized["vocab_unavailable_reason"] == "non_integer_vocab_metric"
    assert materialized["probability_unavailable_reason"] == "negative_support_metric"
    assert validate_evidence_object_invariants(
        {
            "file": "materialized-invalid-metrics.exe",
            "path": "materialized-invalid-metrics.exe",
            "classification": "suspicious",
            "score": 73.0,
            "probability_record": materialized,
        },
        context="stage1293-invalid-metrics-materialized",
    ) is True


def test_stage1293_materialized_invalid_probability_record_reaches_final_json_and_replay_flags() -> None:
    compact = compact_result_record(
        {
            "file": "materialized-invalid-probability-final-json.exe",
            "path": "materialized-invalid-probability-final-json.exe",
            "classification": "suspicious",
            "score": 73.0,
            "tags": ["probability_materializer_signal"],
            "explanation": {"reasons": ["materialized probability record affected model evidence"]},
            "probability_record": materialize_probability_record(
                {
                    "ready": "yes",
                    "probability": 0.91,
                    "support": 8,
                    "count": 7,
                    "vocab": 3,
                    "smoothing": "laplace",
                    "reason": None,
                    "model_version": "probability_record_v1",
                }
            ),
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert probability_record["ready"] is False
    assert probability_record["probability"] is None
    assert probability_record["ready_unavailable_reason"] == "non_boolean_ready_flag"
    assert probability_record["probability_unavailable_reason"] == "not_ready_probability_present"
    assert evidence["unavailable_reasons"]["probability_record.ready"] == "non_boolean_ready_flag"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "not_ready_probability_present"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1293-compact") is True
