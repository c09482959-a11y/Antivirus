from __future__ import annotations

import math

import pytest

from Virus_Scan.contracts.result_record import (
    ResultEvidenceSnapshot,
    normalize_result_record,
    result_has_scan_evidence,
    validate_evidence_object_invariants,
)
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1261_adaptive_learning_counts_as_model_evidence_not_scanner_failure() -> None:
    record = {
        "file": "adaptive-learning.exe",
        "path": "adaptive-learning.exe",
        "classification": "suspicious",
        "score": 84.0,
        "adaptive_learning": {
            "version": "adaptive_weights_v1_profile_markov_cluster",
            "profile": {"profile_ready": True, "profile_anomaly": 0.72},
            "markov": {"markov_anomaly": 0.61},
            "cluster": {"cluster_signal": 0.54},
            "bucket_vector": {
                "bucket_validation": {"bucket_anomaly": 0.44},
                "vector_validation": {"anomaly": 0.42},
            },
            "rolling_learned_static": {"static_weight": 0.7, "learned_model_weight": 0.3},
        },
        "adaptive_weights": {"quick_static": 0.5, "stage_timeline": 0.25, "graph_relationships": 0.25},
    }

    assert result_has_scan_evidence(record)
    assert ResultEvidenceSnapshot.from_record(record).model_evidence_count >= 2

    normalized = normalize_result_record(record, source="stage1261_test")
    assert "result_contract_violation" not in normalized.get("tags", ())
    assert "scanner_failure" not in normalized.get("tags", ())
    assert not normalized.get("error")


def test_stage1261_adaptive_learning_shape_is_validated_as_model_evidence() -> None:
    record = {
        "file": "adaptive-learning.exe",
        "path": "adaptive-learning.exe",
        "classification": "suspicious",
        "score": 84.0,
        "adaptive_learning": {
            "rolling_learned_static": {"learned_model_weight": math.inf},
        },
    }

    with pytest.raises(ValueError, match="adaptive_learning.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1261")

    record.pop("adaptive_learning")
    record["adaptive_weights"] = {"quick_static": math.nan}
    with pytest.raises(ValueError, match="adaptive_weights.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1261")


def test_stage1261_adaptive_learning_compact_summary_and_failure_projection() -> None:
    compact = compact_result_record(
        {
            "file": "adaptive-learning.exe",
            "path": "adaptive-learning.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["adaptive_learning_model_signal"],
            "explanation": {"reasons": ["adaptive learning emitted invalid model value"]},
            "adaptive_learning": {
                "rolling_learned_static": {
                    "static_weight": 0.62,
                    "learned_model_weight": math.inf,
                },
                "bucket_vector": {
                    "bucket_validation": {"bucket_anomaly": math.nan},
                },
            },
            "adaptive_weights": {"quick_static": math.nan, "stage_timeline": 0.2},
            "pre_rolling_weights": {"quick_static": math.inf},
            "rolling_learned_static": {"learned_model_weight": math.inf},
            "bucket_vector": {"vector_validation": {"anomaly": math.nan}},
        }
    )

    assert compact["adaptive_learning_summary"]["rolling_learned_static"]["learned_model_weight"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["adaptive_weights_summary"]["quick_static"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["pre_rolling_weights_summary"]["quick_static"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["rolling_learned_static_summary"]["learned_model_weight"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["bucket_vector_summary"]["vector_validation"]["anomaly"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }

    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence["model_failures"]
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "adaptive_learning"
        for failure in failures
    )
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "adaptive_weights"
        for failure in failures
    )
