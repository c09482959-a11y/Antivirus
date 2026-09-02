from __future__ import annotations

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
)
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1292_probability_record_constructor_does_not_emit_negative_support_as_learned_evidence() -> None:
    record = make_probability_record(
        ready=True,
        probability=0.7,
        support=-1,
        count=5,
        vocab=2,
        smoothing="laplace",
        reason="trained",
        model_version="probability_record_v1",
    )

    materialized = materialize_probability_record(record)

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["support_unavailable_reason"] == "negative_support_metric"
    assert materialized["probability_unavailable_reason"] == "negative_support_metric"
    assert validate_evidence_object_invariants(
        {
            "file": "negative-support-constructor.exe",
            "path": "negative-support-constructor.exe",
            "classification": "suspicious",
            "score": 77.0,
            "probability_record": materialized,
        },
        context="stage1292-negative-support-constructor",
    ) is True


def test_stage1292_probability_record_constructor_does_not_raise_on_non_numeric_metrics() -> None:
    record = make_probability_record(
        ready=True,
        probability=0.7,
        support="many",
        count="few",
        vocab=True,
        smoothing="laplace",
        reason="trained",
        model_version="probability_record_v1",
    )

    materialized = materialize_probability_record(record)

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["support_unavailable_reason"] == "non_numeric_support_metric"
    assert materialized["count_unavailable_reason"] == "non_numeric_count_metric"
    assert materialized["vocab_unavailable_reason"] == "non_numeric_vocab_metric"
    assert materialized["probability_unavailable_reason"] == "non_numeric_support_metric"
    assert validate_evidence_object_invariants(
        {
            "file": "non-numeric-metrics-constructor.exe",
            "path": "non-numeric-metrics-constructor.exe",
            "classification": "suspicious",
            "score": 77.0,
            "probability_record": materialized,
        },
        context="stage1292-non-numeric-metrics-constructor",
    ) is True


def test_stage1292_constructor_metric_unavailability_reaches_final_json_and_replay_flags() -> None:
    compact = compact_result_record(
        {
            "file": "negative-support-final-json.exe",
            "path": "negative-support-final-json.exe",
            "classification": "suspicious",
            "score": 77.0,
            "tags": ["probability_metric_constructor_signal"],
            "explanation": {"reasons": ["constructor metric affected probability evidence"]},
            "probability_record": materialize_probability_record(
                make_probability_record(
                    ready=True,
                    probability=0.7,
                    support=-1,
                    count=5,
                    vocab=2,
                    smoothing="laplace",
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
    assert probability_record["support_unavailable_reason"] == "negative_support_metric"
    assert evidence["unavailable_reasons"]["probability_record.support"] == "negative_support_metric"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "negative_support_metric"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1292-compact") is True
