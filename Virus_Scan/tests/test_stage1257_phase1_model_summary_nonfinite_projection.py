from __future__ import annotations

import json
import math

from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1257_model_feature_summaries_do_not_publish_nonfinite_floats() -> None:
    compact = compact_result_record(
        {
            "file": "nonfinite-model-summary.py",
            "path": "nonfinite-model-summary.py",
            "node": "nonfinite-model-summary.py",
            "score": 52.0,
            "classification": "medium",
            "tags": ["model_summary_evidence"],
            "temporal_features": {
                "stage_probability": math.nan,
                "nested": {"sequence_probability": math.inf},
            },
            "markov_features": {
                "pair_probability": -math.inf,
            },
            "graph_features": {
                "influence": math.nan,
            },
            "explanation": {"reasons": ["non-finite model summary should not publish"]},
        }
    )

    assert compact["temporal_signals"]["model_signal_projection_failed"] is True
    assert compact["markov_sequence_signals"]["model_signal_projection_failed"] is True
    assert compact["graph_signals"]["model_signal_projection_failed"] is True

    assert compact["temporal_features_summary"]["stage_probability"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["temporal_features_summary"]["nested"]["sequence_probability"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["markov_features_summary"]["pair_probability"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }
    assert compact["graph_features_summary"]["influence"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
    }

    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["unavailable_reasons"] == {
        "graph_features": "non_finite_model_signal_value",
        "markov_features": "non_finite_model_signal_value",
        "temporal_features": "non_finite_model_signal_value",
    }
    assert {failure["affected_fields"] for failure in evidence["model_failures"]} == {
        ("graph_features",),
        ("markov_features",),
        ("temporal_features",),
    }
    json.dumps(compact, sort_keys=True, allow_nan=False)
