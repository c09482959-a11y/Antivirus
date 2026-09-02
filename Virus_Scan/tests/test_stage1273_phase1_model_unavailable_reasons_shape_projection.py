from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1273_non_mapping_model_unavailable_reasons_is_result_boundary_invalid() -> None:
    record = {
        "file": "invalid-unavailable-reasons.exe",
        "path": "invalid-unavailable-reasons.exe",
        "classification": "suspicious",
        "score": 84.0,
        "model_evidence": {
            "unavailable_reasons": "cold-start-as-string",
            "final_json_must_record": True,
        },
    }

    with pytest.raises(ValueError, match=r"model_evidence\.unavailable_reasons.*unavailable reasons record must be an object"):
        validate_evidence_object_invariants(record, context="stage1273")


def test_stage1273_upstream_non_mapping_unavailable_reasons_becomes_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "invalid-unavailable-reasons.exe",
            "path": "invalid-unavailable-reasons.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["model_unavailable_reason_signal"],
            "explanation": {"reasons": ["unavailable model evidence affected final JSON visibility"]},
            "model_evidence": {
                "unavailable_reasons": "cold-start-as-string",
                "writer_version": "upstream_writer_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["writer_version"] == "upstream_writer_v1"
    assert (
        evidence["unavailable_reasons"]["model_evidence.unavailable_reasons"]
        == "non_mapping_model_unavailable_reasons_record"
    )
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_failures"] == (
        {
            "model_name": "model_evidence.unavailable_reasons",
            "failure_type": "invalid_model_unavailable_reasons_record",
            "reason": "non_mapping_model_unavailable_reasons_record",
            "affected_fields": ("model_evidence.unavailable_reasons",),
            "model_version": "model_evidence_writer_v1",
            "details": {
                "source_field": "model_evidence.unavailable_reasons",
                "value_type": "str",
                "value_repr": "'cold-start-as-string'",
            },
        },
    )


def test_stage1273_upstream_valid_unavailable_reasons_mapping_is_preserved() -> None:
    compact = compact_result_record(
        {
            "file": "valid-unavailable-reasons.exe",
            "path": "valid-unavailable-reasons.exe",
            "classification": "suspicious",
            "score": 75.0,
            "tags": ["model_unavailable_reason_signal"],
            "model_evidence": {
                "unavailable_reasons": {"temporal": "cold_start", "markov": "missing_snapshot"},
                "writer_version": "upstream_writer_v1",
            },
            "score_metadata": {"feature_probabilities": {"graph": 0.25}},
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["writer_version"] == "upstream_writer_v1"
    assert evidence["feature_probabilities"] == {"graph": 0.25}
    assert evidence["unavailable_reasons"] == {
        "markov": "missing_snapshot",
        "temporal": "cold_start",
    }
    assert "model_failures" not in evidence
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
