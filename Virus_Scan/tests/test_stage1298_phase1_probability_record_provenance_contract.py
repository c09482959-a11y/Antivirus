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
        "probability": 0.72,
        "support": 9,
        "count": 6,
        "vocab": 4,
        "smoothing": "laplace",
        "reason": "trained",
        "source": "stage-a",
        "target": "stage-b",
        "flow": ("stage-a", "stage-b"),
        "model_version": "stage1298_probability_record_v1",
    }
    record.update(overrides)
    return record


def test_stage1298_result_contract_rejects_mutable_probability_record_provenance() -> None:
    with pytest.raises(ValueError, match="source must be non-empty text or null"):
        validate_evidence_object_invariants(
            {"probability_record": _probability_record(source={"mutable": "source"})},
            context="stage1298-source",
        )

    with pytest.raises(ValueError, match="flow must be a sequence of non-empty text"):
        validate_evidence_object_invariants(
            {"probability_record": _probability_record(flow={"b": 2, "a": 1})},
            context="stage1298-flow",
        )


def test_stage1298_constructor_degrades_invalid_source_without_learned_probability() -> None:
    record = make_probability_record(
        ready=True,
        probability=0.72,
        support=9,
        count=6,
        vocab=4,
        smoothing="laplace",
        reason="trained",
        source={"mutable": "source"},
        target="stage-b",
        flow=("stage-a", "stage-b"),
        model_version="stage1298_probability_record_v1",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["source"] is None
    assert record["source_unavailable_reason"] == "non_text_source"
    assert record["probability_unavailable_reason"] == "non_text_source"
    assert validate_evidence_object_invariants(
        {"probability_record": record},
        context="stage1298-constructor-source",
    ) is True


def test_stage1298_materializer_degrades_invalid_flow_without_learned_probability() -> None:
    materialized = materialize_probability_record(
        _probability_record(flow={"b": 2, "a": 1}),
    )

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["flow"] == ()
    assert materialized["flow_unavailable_reason"] == "non_sequence_flow"
    assert materialized["probability_unavailable_reason"] == "non_sequence_flow"
    assert validate_evidence_object_invariants(
        {"probability_record": materialized},
        context="stage1298-materializer-flow",
    ) is True


def test_stage1298_publication_projects_invalid_provenance_as_degraded_model_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "probability-record-invalid-provenance.exe",
            "path": "probability-record-invalid-provenance.exe",
            "classification": "suspicious",
            "score": 73.0,
            "probability_record": _probability_record(
                source={"mutable": "source"},
                target=["mutable", "target"],
                flow={"b": 2, "a": 1},
            ),
        }
    )

    evidence = compact["model_evidence"]
    probability_record = evidence["probability_record"]

    assert "source" not in probability_record
    assert "target" not in probability_record
    assert "flow" not in probability_record
    assert probability_record["source_unavailable_reason"] == "non_text_probability_record_identity"
    assert probability_record["target_unavailable_reason"] == "non_text_probability_record_identity"
    assert probability_record["flow_unavailable_reason"] == "non_sequence_probability_record_flow"
    assert evidence["unavailable_reasons"]["probability_record.source"] == "non_text_probability_record_identity"
    assert evidence["unavailable_reasons"]["probability_record.target"] == "non_text_probability_record_identity"
    assert evidence["unavailable_reasons"]["probability_record.flow"] == "non_sequence_probability_record_flow"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["model_name"] == "probability_record.source"
        and failure["reason"] == "non_text_probability_record_identity"
        for failure in evidence["model_failures"]
    )
    assert validate_evidence_object_invariants(compact, context="stage1298-compact") is True
