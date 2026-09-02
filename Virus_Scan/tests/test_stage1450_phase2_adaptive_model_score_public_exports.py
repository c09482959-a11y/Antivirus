from __future__ import annotations

import Virus_Scan.detection.scoring.adaptive.model_score as model_score


def test_stage1450_adaptive_model_score_all_is_public_only() -> None:
    assert model_score.__all__
    assert all(not name.startswith("_") for name in model_score.__all__)


def test_stage1450_adaptive_model_score_keeps_canonical_public_entries() -> None:
    expected = {
        "adaptive_learned_model_confidence",
        "adaptive_learned_model_weight_from_confidence",
        "build_probability_features",
        "calibrated_log_odds_score_100",
        "hybrid_static_model_evidence_fusion",
        "learn_adaptive_layer_weights",
    }
    assert expected <= set(model_score.__all__)
