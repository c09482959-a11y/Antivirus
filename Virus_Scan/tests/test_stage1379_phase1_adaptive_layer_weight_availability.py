"""Stage 1379 Phase 1 adaptive layer-weight availability boundaries."""
from __future__ import annotations

from unittest.mock import patch

from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.adaptive import evidence_projection
from Virus_Scan.detection.scoring.adaptive import model_caps


def _zero_model_signal_patches():
    return (
        patch.object(
            model_caps,
            "model_adaptive_profile_signal",
            lambda *args, **kwargs: {
                "profile_ready": True,
                "profile_anomaly": 0.0,
                "files_seen": model_score.ADAPTIVE_WEIGHT_MIN_HISTORY,
                "engine": "unity",
            },
        ),
        patch.object(model_caps, "model_adaptive_markov_signal", lambda *args, **kwargs: {"markov_anomaly": 0.0}),
        patch.object(model_caps, "model_adaptive_cluster_signal", lambda *args, **kwargs: {"cluster_signal": 0.0}),
        patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"bucket_anomaly": 0.0},
                "vector_validation": {"anomaly": 0.0},
                "timeline_validation": {"anomaly": 0.0},
            },
        ),
    )

def test_stage1379_unavailable_quick_and_stage_scores_do_not_shift_adaptive_weights() -> None:
    with _zero_model_signal_patches()[0], _zero_model_signal_patches()[1], _zero_model_signal_patches()[2], _zero_model_signal_patches()[3]:
        _weights, meta = model_score.learn_adaptive_layer_weights(
            node="stage1379-unavailable-static.exe",
            tags=["process_exec", "network_download"],
            
            quick={"score": 99.0, "unavailable_reason": "quick_static_failed"},
            stage={"score": 99.0, "stage_unavailable_reason": "stage_timeline_failed"},
            graph={"score": 0.0},
            intel={"score": 0.0},
            ordered_events=[],
        )

    assert meta["pre_rolling_weights"] == {
        "quick_static": 0.28,
        "stage_timeline": 0.22,
        "graph_relationships": 0.2,
        "threat_intel": 0.3,
    }
    assert meta["rolling_learned_static"]["static_anchor_score"] == 0.0
    assert meta["layer_unavailable_reasons"] == {
        "quick_static": "quick_static_failed",
        "stage_timeline": "stage_timeline_failed",
    }


def test_stage1379_unavailable_quick_score_cannot_create_static_anchor_contradiction_cap() -> None:
    with _zero_model_signal_patches()[0], _zero_model_signal_patches()[1], _zero_model_signal_patches()[2], _zero_model_signal_patches()[3]:
        _weights, meta = model_score.learn_adaptive_layer_weights(
            node="stage1379-quick-anchor.exe",
            tags=["process_exec", "network_download"],
            
            quick={"score": 100.0, "degraded": True},
            stage={"score": 0.0},
            graph={"score": 0.0},
            intel={"score": 0.0},
            ordered_events=[],
        )

    assert meta["rolling_learned_static"]["static_anchor_score"] == 0.0
    assert "static_anchor_overrides_weak_model" not in meta["rolling_learned_static"]["caps_applied"]
    assert meta["layer_unavailable_reasons"] == {
        "quick_static": "degraded_layer_weight_signal",
    }
