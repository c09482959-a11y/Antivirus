from __future__ import annotations

import json
import math

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def test_stage1254_publication_rejects_non_finite_and_out_of_bounds_model_probabilities() -> None:
    fields = build_model_evidence_final_json_fields(
        {
            "score_metadata": {
                "feature_probabilities": {
                    "markov": math.nan,
                    "temporal": math.inf,
                    "graph": 1.5,
                    "profile": 0.75,
                }
            }
        }
    )

    evidence = fields["model_evidence"]
    assert evidence["feature_probabilities"] == {"profile": 0.75}
    assert evidence["unavailable_reasons"] == {
        "graph": "out_of_bounds_probability",
        "markov": "non_finite_probability",
        "temporal": "non_finite_probability",
    }
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert [failure["failure_type"] for failure in evidence["model_failures"]] == [
        "invalid_model_probability",
        "invalid_model_probability",
        "invalid_model_probability",
    ]
    assert {failure["affected_fields"] for failure in evidence["model_failures"]} == {
        ("graph",),
        ("markov",),
        ("temporal",),
    }
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1254_compact_final_json_never_publishes_non_finite_model_probability_values() -> None:
    compact = compact_result_record(
        {
            "file": "sample.py",
            "path": "sample.py",
            "node": "sample.py",
            "score": 44.0,
            "classification": "medium",
            "tags": ["model_probability_evidence"],
            "score_metadata": {
                "feature_probabilities": {
                    "markov": math.nan,
                    "temporal": -0.1,
                    "cluster": 0.25,
                }
            },
            "explanation": {"reasons": ["model probability bounds"]},
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"cluster": 0.25}
    assert evidence["unavailable_reasons"] == {
        "markov": "non_finite_probability",
        "temporal": "out_of_bounds_probability",
    }
    assert {failure["reason"] for failure in evidence["model_failures"]} == {
        "non_finite_probability",
        "out_of_bounds_probability",
    }
    json.dumps(evidence, sort_keys=True, allow_nan=False)


@pytest.mark.parametrize("field", ["model_evidence", "feature_probabilities"])
def test_stage1254_result_contract_rejects_non_finite_model_evidence_scalars(field: str) -> None:
    with pytest.raises(ValueError, match="non-finite float"):
        validate_evidence_object_invariants(
            {field: {"markov": math.nan}},
            context="stage1254_model_probability_bounds",
        )
