from __future__ import annotations

from Virus_Scan.publication.json_writer import compact_result_record


def _model_evidence_from(record: dict[str, object]) -> dict[str, object]:
    compact = compact_result_record(record)
    evidence = compact.get("model_evidence")
    assert isinstance(evidence, dict)
    return evidence


def test_stage1265_upstream_model_evidence_feature_probabilities_are_bounded() -> None:
    evidence = _model_evidence_from(
        {
            "file": "upstream-model-evidence.exe",
            "path": "upstream-model-evidence.exe",
            "classification": "suspicious",
            "score": 88.0,
            "tags": ["upstream_model_evidence"],
            "model_evidence": {
                "feature_probabilities": {
                    "markov": 1.5,
                    "temporal": 0.25,
                    "profile_unavailable_reason": "cold_start",
                },
                "final_json_must_record": True,
                "replay_record_required": True,
            },
        }
    )

    probabilities = evidence.get("feature_probabilities")
    assert isinstance(probabilities, dict)
    assert probabilities["temporal"] == 0.25
    assert "markov" not in probabilities
    assert "profile_unavailable_reason" not in probabilities

    unavailable = evidence.get("unavailable_reasons")
    assert isinstance(unavailable, dict)
    assert unavailable["markov"] == "out_of_bounds_probability"
    assert unavailable["profile"] == "cold_start"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence.get("model_failures")
    assert isinstance(failures, tuple)
    assert any(
        isinstance(failure, dict)
        and failure.get("failure_type") == "invalid_model_probability"
        and failure.get("model_name") == "markov_probability"
        for failure in failures
    )


def test_stage1265_secondary_upstream_model_evidence_probability_failure_is_recorded() -> None:
    evidence = _model_evidence_from(
        {
            "file": "secondary-upstream-model-evidence.exe",
            "path": "secondary-upstream-model-evidence.exe",
            "classification": "suspicious",
            "score": 89.0,
            "tags": ["secondary_upstream_model_evidence"],
            "feature_probabilities": {"markov": 0.2},
            "model_evidence": {
                "feature_probabilities": {"temporal": -0.1},
            },
        }
    )

    probabilities = evidence.get("feature_probabilities")
    assert isinstance(probabilities, dict)
    assert probabilities["markov"] == 0.2
    assert "temporal" not in probabilities

    unavailable = evidence.get("unavailable_reasons")
    assert isinstance(unavailable, dict)
    assert unavailable["model_evidence.feature_probabilities.temporal"] == "out_of_bounds_probability"
    failures = evidence.get("model_failures")
    assert isinstance(failures, tuple)
    assert any(
        isinstance(failure, dict)
        and failure.get("failure_type") == "invalid_model_probability"
        and failure.get("model_name") == "model_evidence.feature_probabilities.temporal"
        for failure in failures
    )
