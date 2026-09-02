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


def test_stage1263_model_context_features_count_as_model_evidence_not_scanner_failure() -> None:
    record = {
        "file": "model-context.exe",
        "path": "model-context.exe",
        "classification": "suspicious",
        "score": 88.0,
        "graph_features": {"risk": 0.82, "anomaly": 0.44},
        "temporal_features": {"belief": 0.71, "transition_age": 3},
        "markov_features": {"transition": 0.18, "rarity": 0.64},
        "model_context": {
            "cluster_id": "cluster-7",
            "graph_features": {"risk": 0.82},
            "temporal_features": {"belief": 0.71},
            "markov_features": {"rarity": 0.64},
        },
    }

    assert result_has_scan_evidence(record)
    snapshot = ResultEvidenceSnapshot.from_record(record)
    assert snapshot.model_evidence_count >= 4

    normalized = normalize_result_record(record, source="stage1263_test")
    assert "result_contract_violation" not in normalized.get("tags", ())
    assert "scanner_failure" not in normalized.get("tags", ())
    assert not normalized.get("error")


def test_stage1263_model_context_feature_shapes_are_validated_as_model_evidence() -> None:
    record = {
        "file": "model-context.exe",
        "path": "model-context.exe",
        "classification": "suspicious",
        "score": 88.0,
        "graph_features": {"risk": math.inf},
    }

    with pytest.raises(ValueError, match="graph_features.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1263")

    record.pop("graph_features")
    record["model_context"] = {"temporal_features": {"belief": math.nan}}
    with pytest.raises(ValueError, match="model_context.*non-finite float"):
        validate_evidence_object_invariants(record, context="stage1263")


def test_stage1263_context_model_summaries_and_failures_are_final_json_visible() -> None:
    compact = compact_result_record(
        {
            "file": "model-context.exe",
            "path": "model-context.exe",
            "classification": "suspicious",
            "score": 88.0,
            "tags": ["model_context_feature_signal"],
            "explanation": {"reasons": ["model context features were output-affecting"]},
            "graph_features": {"risk": math.inf, "anomaly": 0.42},
            "temporal_features": {"belief": math.nan},
            "markov_features": {"transition": 0.2, "rarity": math.inf},
            "model_context": {
                "graph_features": {"risk": math.inf},
                "temporal_features": {"belief": 0.4},
            },
            "contextual_expected_behavior": {"reduction": math.nan},
            "context_confidence_amplifier": {"amplifier": math.inf},
        }
    )

    assert compact["graph_features_summary"]["risk"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["temporal_features_summary"]["belief"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["markov_features_summary"]["rarity"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["model_context_summary"]["graph_features"]["risk"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["contextual_expected_behavior_summary"]["reduction"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["context_confidence_amplifier_summary"]["amplifier"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }

    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    failures = evidence["model_failures"]
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "graph_features"
        for failure in failures
    )
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "model_context"
        for failure in failures
    )
    assert any(
        failure["failure_type"] == "model_signal_projection_failed"
        and failure["model_name"] == "contextual_expected_behavior"
        for failure in failures
    )
