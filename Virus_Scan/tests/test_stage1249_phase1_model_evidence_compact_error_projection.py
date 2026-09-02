from __future__ import annotations

from collections.abc import Mapping
import json

from Virus_Scan.models.contracts.model_failure import make_model_failure_record
from Virus_Scan.publication import json_writer
from Virus_Scan.publication.json_writer import compact_result_record


def _model_failure_record() -> dict[str, object]:
    failure = make_model_failure_record(
        model_name="adaptive_probability_features",
        failure_type="feature_build_failed",
        reason="probability_feature_build_failed",
        affected_fields={"p_temporal", "p_markov"},
        details={"source": "compact_error_projection"},
        model_version="stage1249_compact_error_projection",
    )
    return {
        "path": "sample.py",
        "score": 44.0,
        "classification": "medium",
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


def test_stage1249_compact_error_record_preserves_preexisting_model_failure_evidence() -> None:
    compact = json_writer.build_compact_error_record(
        json_writer.normalize_compact_result_record(_model_failure_record()),
        RuntimeError("forced compact failure"),
    )

    assert compact["final_status"] == "compact_record_error"
    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["feature_probabilities"] == {"markov": 0.0, "temporal": 0.0}
    assert evidence["unavailable_reasons"] == {
        "markov": "probability_feature_build_failed",
        "temporal": "probability_feature_build_failed",
    }
    assert evidence["model_failures"][0]["reason"] == "probability_feature_build_failed"
    json.dumps(evidence, sort_keys=True)


def test_stage1249_normal_compact_path_still_projects_model_failure_evidence() -> None:
    compact = compact_result_record(_model_failure_record())

    assert compact["final_status"] in {"completed", "completed_nonzero_exit"}
    assert compact["model_evidence"]["model_failures"][0]["failure_type"] == "feature_build_failed"


class _ExplodingFeatureProbabilities(Mapping[str, object]):
    touched = 0

    def __iter__(self):
        _ExplodingFeatureProbabilities.touched += 1
        raise RuntimeError("feature probability payload unavailable")

    def __len__(self):
        _ExplodingFeatureProbabilities.touched += 1
        raise RuntimeError("feature probability payload unavailable")

    def __getitem__(self, key: str) -> object:
        _ExplodingFeatureProbabilities.touched += 1
        raise RuntimeError("feature probability payload unavailable")

    def get(self, key: str, default: object = None) -> object:
        _ExplodingFeatureProbabilities.touched += 1
        raise RuntimeError("feature probability payload unavailable")

    def items(self):
        _ExplodingFeatureProbabilities.touched += 1
        raise RuntimeError("feature probability payload unavailable")


def test_stage1249_model_evidence_projection_failure_becomes_explicit_evidence() -> None:
    _ExplodingFeatureProbabilities.touched = 0

    compact = compact_result_record(
        {
            "path": "bad-model-evidence.py",
            "score": 44.0,
            "classification": "medium",
            "tags": ["model_failure_evidence"],
            "score_metadata": {"feature_probabilities": _ExplodingFeatureProbabilities()},
            "explanation": {"reasons": ["model probability unavailable"]},
        }
    )

    evidence = compact["model_evidence"]
    assert _ExplodingFeatureProbabilities.touched == 0
    assert evidence["writer_version"] == "model_evidence_writer_v1"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["unavailable_reasons"]["score_metadata.feature_probabilities"] == "unreadable_model_evidence_mapping"
    assert any(
        failure["reason"] == "unreadable_model_evidence_mapping"
        and failure["model_name"] == "score_metadata.feature_probabilities"
        for failure in evidence["model_failures"]
    )
    json.dumps(evidence, sort_keys=True)
