from __future__ import annotations

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import materialize_probability_record
from Virus_Scan.publication.json_writer import compact_result_record


def _probability_record(**overrides):
    record = {
        "ready": True,
        "probability": 0.83,
        "support": 13,
        "count": 9,
        "vocab": 6,
        "smoothing": "laplace",
        "reason": "trained",
        "source": "stage-a",
        "target": "stage-b",
        "flow": ("stage-a", "stage-b"),
        "model_version": "stage1302_probability_record_v1",
    }
    record.update(overrides)
    return record


def test_stage1302_materializer_suppresses_probability_when_metric_unavailable_reason_is_present() -> None:
    materialized = materialize_probability_record(
        _probability_record(support_unavailable_reason="explicit_support_degraded")
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["support_unavailable_reason"] == "explicit_support_degraded"
    assert materialized["probability_unavailable_reason"] == "explicit_support_degraded"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1302-materialized-explicit-support-unavailable",
    ) is True


def test_stage1302_materializer_suppresses_probability_when_provenance_unavailable_reason_is_present() -> None:
    materialized = materialize_probability_record(
        _probability_record(source_unavailable_reason="explicit_source_degraded")
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["source_unavailable_reason"] == "explicit_source_degraded"
    assert materialized["probability_unavailable_reason"] == "explicit_source_degraded"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1302-materialized-explicit-source-unavailable",
    ) is True


def test_stage1302_publication_records_explicit_unavailable_reason_degradation() -> None:
    materialized = materialize_probability_record(
        _probability_record(support_unavailable_reason="explicit_support_degraded")
    )
    compact = compact_result_record(
        {
            "file": "probability-record-explicit-unavailable-reason.exe",
            "path": "probability-record-explicit-unavailable-reason.exe",
            "classification": "suspicious",
            "score": 73.0,
            "probability_record": materialized,
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert probability_record["ready"] is False
    assert probability_record["probability"] is None
    assert probability_record["support_unavailable_reason"] == "explicit_support_degraded"
    assert probability_record["probability_unavailable_reason"] == "explicit_support_degraded"
    assert evidence["unavailable_reasons"]["probability_record.support"] == "explicit_support_degraded"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "explicit_support_degraded"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert validate_evidence_object_invariants(compact, context="stage1302-compact") is True
