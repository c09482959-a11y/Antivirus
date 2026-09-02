from __future__ import annotations

import json

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def test_stage1250_model_evidence_writer_preserves_upstream_required_flags_without_new_failures() -> None:
    fields = build_model_evidence_final_json_fields(
        {
            "model_evidence": {
                "writer_version": "upstream_model_evidence_v1",
                "final_json_must_record": True,
                "replay_record_required": True,
                "model_failures": (
                    {
                        "model_name": "profile_snapshot",
                        "failure_type": "invalid_profile",
                        "reason": "schema_version_mismatch",
                    },
                ),
            },
            "score_metadata": {"feature_probabilities": {"markov": 0.25}},
        }
    )

    evidence = fields["model_evidence"]
    assert evidence["writer_version"] == "upstream_model_evidence_v1"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_failures"][0]["failure_type"] == "invalid_profile"
    assert evidence["feature_probabilities"] == {"markov": 0.25}
    json.dumps(evidence, sort_keys=True)


def test_stage1250_compact_final_json_merges_upstream_and_scoring_model_failures() -> None:
    compact = compact_result_record(
        {
            "path": "sample.py",
            "score": 51.0,
            "classification": "medium",
            "tags": ["model_failure_evidence"],
            "model_evidence": {
                "final_json_must_record": True,
                "replay_record_required": True,
                "feature_probabilities": {"profile": 0.4},
                "model_failures": (
                    {
                        "model_name": "profile_snapshot",
                        "failure_type": "invalid_profile",
                        "reason": "schema_version_mismatch",
                    },
                ),
            },
            "score_metadata": {
                "feature_probabilities": {
                    "markov": 0.0,
                    "markov_unavailable_reason": "cold_start",
                    "model_failure": {
                        "model_name": "adaptive_probability_features",
                        "failure_type": "feature_build_failed",
                        "reason": "probability_feature_build_failed",
                    },
                }
            },
            "explanation": {"reasons": ["model evidence merge"]},
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["feature_probabilities"] == {"profile": 0.4, "markov": 0.0}
    assert evidence["unavailable_reasons"] == {"markov": "cold_start"}
    assert [failure["failure_type"] for failure in evidence["model_failures"]] == [
        "invalid_profile",
        "feature_build_failed",
    ]
    json.dumps(evidence, sort_keys=True)
