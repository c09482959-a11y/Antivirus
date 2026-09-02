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
        "probability": 0.58,
        "support": 4,
        "count": 3,
        "vocab": 6,
        "smoothing": "laplace",
        "reason": "trained",
        "model_version": "stage1295_probability_record_v1",
    }
    record.update(overrides)
    return record


def test_stage1295_result_contract_rejects_blank_probability_record_smoothing() -> None:
    with pytest.raises(ValueError, match="smoothing must be non-empty text"):
        validate_evidence_object_invariants(
            {"probability_record": _probability_record(smoothing="")},
            context="stage1295-blank-smoothing",
        )


def test_stage1295_result_contract_rejects_blank_probability_record_model_version() -> None:
    with pytest.raises(ValueError, match="model_version must be non-empty text"):
        validate_evidence_object_invariants(
            {"probability_record": _probability_record(model_version="")},
            context="stage1295-blank-model-version",
        )


def test_stage1295_constructor_degrades_invalid_text_metadata_without_learned_probability() -> None:
    record = make_probability_record(
        ready=True,
        probability=0.58,
        support=4,
        count=3,
        vocab=6,
        smoothing="",
        reason=None,
        model_version="",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["smoothing"] == "none"
    assert record["model_version"] == "probability_record_v1"
    assert record["smoothing_unavailable_reason"] == "blank_smoothing"
    assert record["model_version_unavailable_reason"] == "blank_model_version"
    assert record["probability_unavailable_reason"] == "blank_smoothing"
    assert validate_evidence_object_invariants(
        {"probability_record": record},
        context="stage1295-constructor-invalid-text-metadata",
    ) is True


def test_stage1295_materializer_degrades_invalid_text_metadata_without_learned_probability() -> None:
    materialized = materialize_probability_record(
        {
            "ready": True,
            "probability": 0.58,
            "support": 4,
            "count": 3,
            "vocab": 6,
            "smoothing": {},
            "reason": "trained",
            "model_version": "",
        }
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["smoothing_unavailable_reason"] == "non_text_smoothing"
    assert materialized["model_version_unavailable_reason"] == "blank_model_version"
    assert materialized["probability_unavailable_reason"] == "non_text_smoothing"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1295-materialized-invalid-text-metadata",
    ) is True


def test_stage1295_publication_projects_blank_text_metadata_as_degraded_model_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "probability-record-text-metadata.exe",
            "path": "probability-record-text-metadata.exe",
            "classification": "suspicious",
            "score": 73.0,
            "probability_record": _probability_record(smoothing="", model_version=""),
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert "smoothing" not in probability_record
    assert "model_version" not in probability_record
    assert probability_record["smoothing_unavailable_reason"] == "blank_probability_record_field"
    assert probability_record["model_version_unavailable_reason"] == "blank_probability_record_field"
    assert evidence["unavailable_reasons"]["probability_record.smoothing"] == "blank_probability_record_field"
    assert evidence["unavailable_reasons"]["probability_record.model_version"] == "blank_probability_record_field"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["model_name"] == "probability_record.smoothing"
        and failure["reason"] == "blank_probability_record_field"
        for failure in evidence["model_failures"]
    )
    assert any(
        failure["model_name"] == "probability_record.model_version"
        and failure["reason"] == "blank_probability_record_field"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1295-compact") is True
