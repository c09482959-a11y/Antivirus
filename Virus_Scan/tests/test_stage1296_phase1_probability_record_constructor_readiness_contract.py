from __future__ import annotations

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import make_probability_record
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1296_constructor_does_not_coerce_non_boolean_ready_into_learned_probability() -> None:
    record = make_probability_record(
        ready="yes",
        probability=0.91,
        support=8,
        count=7,
        vocab=3,
        smoothing="laplace",
        reason=None,
        model_version="stage1296_probability_record_v1",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["ready_unavailable_reason"] == "non_boolean_ready_flag"
    assert record["probability_unavailable_reason"] == "not_ready_probability_present"
    assert record["reason"] == "not_ready_probability_present"
    assert validate_evidence_object_invariants(
        {"probability_record": record},
        context="stage1296-constructor-non-boolean-ready",
    ) is True


def test_stage1296_constructor_does_not_drop_probability_when_ready_false_without_reason() -> None:
    record = make_probability_record(
        ready=False,
        probability=0.77,
        support=6,
        count=5,
        vocab=2,
        smoothing="laplace",
        reason=None,
        model_version="stage1296_probability_record_v1",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["probability_unavailable_reason"] == "not_ready_probability_present"
    assert record["reason"] == "not_ready_probability_present"
    assert validate_evidence_object_invariants(
        {"probability_record": record},
        context="stage1296-constructor-ready-false-probability-present",
    ) is True


def test_stage1296_constructor_readiness_degradation_reaches_final_json_and_replay_flags() -> None:
    compact = compact_result_record(
        {
            "file": "constructor-readiness-probability-record.exe",
            "path": "constructor-readiness-probability-record.exe",
            "classification": "suspicious",
            "score": 73.0,
            "tags": ["probability_constructor_signal"],
            "explanation": {"reasons": ["constructor probability record affected model evidence"]},
            "probability_record": make_probability_record(
                ready="yes",
                probability=0.91,
                support=8,
                count=7,
                vocab=3,
                smoothing="laplace",
                reason=None,
                model_version="stage1296_probability_record_v1",
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
    assert validate_evidence_object_invariants(compact, context="stage1296-compact") is True
