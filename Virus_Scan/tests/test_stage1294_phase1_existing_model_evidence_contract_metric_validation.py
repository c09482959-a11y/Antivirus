import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def _existing_probability_record(**overrides):
    record = {
        "ready": True,
        "probability": 0.75,
        "support": 3,
        "count": 2,
        "vocab": 5,
        "smoothing": "laplace",
        "reason": "trained",
        "model_version": "test_probability_record_v1",
    }
    record.update(overrides)
    return record


def test_existing_model_evidence_probability_record_rejects_out_of_bounds_probability():
    result = {
        "model_evidence": {
            "probability_record": _existing_probability_record(probability=2.0),
        }
    }

    with pytest.raises(ValueError, match="probability out of bounds"):
        validate_evidence_object_invariants(result)


def test_existing_model_evidence_probability_record_rejects_non_boolean_ready():
    result = {
        "model_evidence": {
            "probability_record": _existing_probability_record(ready="yes"),
        }
    }

    with pytest.raises(ValueError, match="readiness flag must be boolean"):
        validate_evidence_object_invariants(result)


def test_existing_model_evidence_probability_record_rejects_negative_support():
    result = {
        "model_evidence": {
            "probability_record": _existing_probability_record(support=-1),
        }
    }

    with pytest.raises(ValueError, match="count/support metric must be non-negative"):
        validate_evidence_object_invariants(result)


def test_publication_projects_existing_model_evidence_probability_record_degradation():
    result = {
        "model_evidence": {
            "probability_record": _existing_probability_record(probability=2.0),
        }
    }

    projected = build_model_evidence_final_json_fields(result)["model_evidence"]

    assert projected["probability_record"]["probability_unavailable_reason"] == "out_of_bounds_probability"
    assert projected["unavailable_reasons"]["probability_record.probability"] == "out_of_bounds_probability"
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
    assert any(
        failure["model_name"] == "probability_record.probability"
        and failure["reason"] == "out_of_bounds_probability"
        for failure in projected["model_failures"]
    )
