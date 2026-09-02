from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.models.contracts.model_failure import make_model_failure_record
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


PUBLICATION_WRITER = Path("Virus_Scan/publication/model_evidence_projection/api.py")


def _record_with_model_failure():
    failure = make_model_failure_record(
        model_name="adaptive_probability_features",
        failure_type="feature_build_failed",
        reason="probability_feature_build_failed",
        affected_fields={"p_markov", "p_temporal"},
        details={"paths": ["b", "a"]},
        model_version="stage1248_projection_test",
    )
    return {
        "file": "sample.py",
        "path": "sample.py",
        "node": "sample.py",
        "score": 33.0,
        "classification": "low_confidence",
        "tags": ["model_failure_evidence"],
        "score_metadata": {
            "feature_probabilities": {
                "markov": 0.0,
                "markov_unavailable_reason": "probability_feature_build_failed",
                "temporal": 0.0,
                "temporal_unavailable_reason": "probability_feature_build_failed",
                "model_failure": failure,
            }
        },
        "explanation": {"reasons": ["model probability unavailable"]},
    }


def test_stage1248_publication_projects_model_failure_to_final_json() -> None:
    compact = compact_result_record(_record_with_model_failure())

    model_evidence = compact["model_evidence"]
    assert model_evidence["writer_version"] == "model_evidence_writer_v1"
    assert model_evidence["final_json_must_record"] is True
    assert model_evidence["replay_record_required"] is True
    assert model_evidence["feature_probabilities"] == {"markov": 0.0, "temporal": 0.0}
    assert model_evidence["unavailable_reasons"] == {
        "markov": "probability_feature_build_failed",
        "temporal": "probability_feature_build_failed",
    }
    failure = model_evidence["model_failures"][0]
    assert failure["reason"] == "probability_feature_build_failed"
    assert failure["affected_fields"] == ("p_markov", "p_temporal")
    json.dumps(model_evidence, sort_keys=True)


def test_stage1248_model_evidence_projection_is_deterministic_and_detached() -> None:
    record = _record_with_model_failure()
    first = build_model_evidence_final_json_fields(record)
    second = build_model_evidence_final_json_fields(record)
    assert first == second

    record["score_metadata"]["feature_probabilities"]["markov"] = 1.0
    assert first["model_evidence"]["feature_probabilities"]["markov"] == 0.0


def test_stage1248_publication_writer_does_not_recompute_model_probabilities() -> None:
    text = PUBLICATION_WRITER.read_text(encoding="utf-8")
    forbidden = (
        "calibrated_log_odds_score_100",
        "build_probability_features",
        "Virus_Scan.detection.scoring.adaptive.model_score",
        "Virus_Scan.models.markov",
        "Virus_Scan.models.temporal",
        "Virus_Scan.models.graph",
        "Virus_Scan.models.clustering",
        "Virus_Scan.models.profiles",
    )
    for token in forbidden:
        assert token not in text
