from __future__ import annotations

import json
import math

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1275_non_text_feature_unavailable_reason_is_result_boundary_invalid() -> None:
    record = {
        "file": "invalid-feature-unavailable-reason.exe",
        "path": "invalid-feature-unavailable-reason.exe",
        "classification": "suspicious",
        "score": 82.0,
        "feature_probabilities": {
            "markov": 0.41,
            "markov_unavailable_reason": {"reason": "cold_start"},
        },
    }

    with pytest.raises(ValueError, match=r"feature_probabilities\.markov_unavailable_reason.*unavailable reason"):
        validate_evidence_object_invariants(record, context="stage1275")


def test_stage1275_invalid_feature_unavailable_reason_values_become_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "invalid-feature-unavailable-reason.exe",
            "path": "invalid-feature-unavailable-reason.exe",
            "classification": "suspicious",
            "score": 82.0,
            "tags": ["feature_unavailable_reason_signal"],
            "explanation": {"reasons": ["feature unavailable reason values affected final JSON visibility"]},
            "feature_probabilities": {
                "markov": 0.41,
                "markov_unavailable_reason": math.nan,
                "profile_unavailable_reason": "",
                "temporal_unavailable_reason": " cold_start ",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.41}
    assert evidence["unavailable_reasons"] == {
        "feature_probabilities.markov_unavailable_reason": "non_text_model_unavailable_reason",
        "feature_probabilities.profile_unavailable_reason": "empty_model_unavailable_reason",
        "temporal": "cold_start",
    }
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence["model_failures"]
    assert {failure["model_name"] for failure in failures} == {
        "feature_probabilities.markov_unavailable_reason",
        "feature_probabilities.profile_unavailable_reason",
    }
    assert {failure["failure_type"] for failure in failures} == {"invalid_model_unavailable_reason"}
    assert {failure["reason"] for failure in failures} == {
        "non_text_model_unavailable_reason",
        "empty_model_unavailable_reason",
    }
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1275_valid_feature_unavailable_reason_text_is_preserved() -> None:
    compact = compact_result_record(
        {
            "file": "valid-feature-unavailable-reason.exe",
            "path": "valid-feature-unavailable-reason.exe",
            "classification": "medium",
            "score": 52.0,
            "tags": ["feature_unavailable_reason_signal"],
            "feature_probabilities": {
                "markov": 0.25,
                "markov_unavailable_reason": " missing_snapshot ",
                "temporal_unavailable_reason": None,
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.25}
    assert evidence["unavailable_reasons"] == {"markov": "missing_snapshot"}
    assert "model_failures" not in evidence
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
