from __future__ import annotations

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.contracts.probability_record import materialize_probability_record
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1300_materializer_does_not_default_missing_required_metrics_to_learned_evidence() -> None:
    materialized = materialize_probability_record(
        {
            "ready": True,
            "probability": 0.9,
            "smoothing": "laplace",
            "model_version": "stage1300_probability_record_v1",
        }
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["support"] == 0
    assert materialized["count"] == 0
    assert materialized["vocab"] == 0
    assert materialized["support_unavailable_reason"] == "missing_probability_record_field"
    assert materialized["count_unavailable_reason"] == "missing_probability_record_field"
    assert materialized["vocab_unavailable_reason"] == "missing_probability_record_field"
    assert materialized["reason_unavailable_reason"] == "missing_probability_record_field"
    assert materialized["probability_unavailable_reason"] == "missing_probability_record_field"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1300-materialized-missing-required-metrics",
    ) is True


def test_stage1300_materializer_does_not_default_missing_text_metadata_to_learned_evidence() -> None:
    materialized = materialize_probability_record(
        {
            "ready": True,
            "probability": 0.82,
            "support": 6,
            "count": 4,
            "vocab": 2,
        }
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["smoothing"] == "none"
    assert materialized["model_version"] == "probability_record_v1"
    assert materialized["smoothing_unavailable_reason"] == "missing_probability_record_field"
    assert materialized["model_version_unavailable_reason"] == "missing_probability_record_field"
    assert materialized["reason_unavailable_reason"] == "missing_probability_record_field"
    assert materialized["probability_unavailable_reason"] == "missing_probability_record_field"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1300-materialized-missing-text-metadata",
    ) is True


def test_stage1300_materialized_missing_required_fields_reach_final_json_and_replay_flags() -> None:
    compact = compact_result_record(
        {
            "file": "materialized-missing-required-fields.exe",
            "path": "materialized-missing-required-fields.exe",
            "classification": "suspicious",
            "score": 78.0,
            "probability_record": materialize_probability_record(
                {
                    "ready": True,
                    "probability": 0.9,
                    "smoothing": "laplace",
                    "model_version": "stage1300_probability_record_v1",
                }
            ),
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert probability_record["ready"] is False
    assert probability_record["probability"] is None
    assert probability_record["support_unavailable_reason"] == "missing_probability_record_field"
    assert probability_record["count_unavailable_reason"] == "missing_probability_record_field"
    assert probability_record["vocab_unavailable_reason"] == "missing_probability_record_field"
    assert evidence["unavailable_reasons"]["probability_record.support"] == "missing_probability_record_field"
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "missing_probability_record_field"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert "model_failures" not in evidence or all(
        failure.get("failure_type") != "clean_model_fallback"
        for failure in evidence.get("model_failures", ())
    )
    assert validate_evidence_object_invariants(compact, context="stage1300-compact") is True
