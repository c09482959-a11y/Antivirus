from __future__ import annotations

import json
import math

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1274_non_text_model_unavailable_reason_value_is_result_boundary_invalid() -> None:
    record = {
        "file": "invalid-unavailable-reason-value.exe",
        "path": "invalid-unavailable-reason-value.exe",
        "classification": "suspicious",
        "score": 84.0,
        "model_evidence": {
            "unavailable_reasons": {"markov": {"reason": "cold_start"}},
            "final_json_must_record": True,
        },
    }

    with pytest.raises(ValueError, match=r"model_evidence\.unavailable_reasons\.markov.*unavailable reason must be non-empty text"):
        validate_evidence_object_invariants(record, context="stage1274")


def test_stage1274_upstream_invalid_unavailable_reason_values_become_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "invalid-unavailable-reason-value.exe",
            "path": "invalid-unavailable-reason-value.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["model_unavailable_reason_signal"],
            "explanation": {"reasons": ["unavailable model reason values affected final JSON visibility"]},
            "model_evidence": {
                "unavailable_reasons": {
                    "markov": math.nan,
                    "profile": "",
                    "temporal": "cold_start",
                },
                "writer_version": "upstream_writer_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["writer_version"] == "upstream_writer_v1"
    assert evidence["unavailable_reasons"] == {
        "model_evidence.unavailable_reasons.markov": "non_text_model_unavailable_reason",
        "model_evidence.unavailable_reasons.profile": "empty_model_unavailable_reason",
        "temporal": "cold_start",
    }
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence["model_failures"]
    assert {failure["model_name"] for failure in failures} == {
        "model_evidence.unavailable_reasons.markov",
        "model_evidence.unavailable_reasons.profile",
    }
    assert {failure["reason"] for failure in failures} == {
        "non_text_model_unavailable_reason",
        "empty_model_unavailable_reason",
    }
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1274_upstream_valid_unavailable_reason_text_values_are_preserved() -> None:
    compact = compact_result_record(
        {
            "file": "valid-unavailable-reason-values.exe",
            "path": "valid-unavailable-reason-values.exe",
            "classification": "suspicious",
            "score": 75.0,
            "tags": ["model_unavailable_reason_signal"],
            "model_evidence": {
                "unavailable_reasons": {"temporal": " cold_start ", "markov": "missing_snapshot"},
                "writer_version": "upstream_writer_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["unavailable_reasons"] == {
        "markov": "missing_snapshot",
        "temporal": "cold_start",
    }
    assert "model_failures" not in evidence
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
