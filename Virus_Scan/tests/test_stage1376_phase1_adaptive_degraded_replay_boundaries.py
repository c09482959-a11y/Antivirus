"""Stage 1376 Phase 1 adaptive degraded replay boundary repairs."""
from __future__ import annotations
from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture

from Virus_Scan.detection.scoring.adaptive import model_score


def _log_odds_with_learning(adaptive_learning):
    return model_score.calibrated_log_odds_score_100(
        raw_weighted_score=30.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=[]),
        tags=[],
        yara_hits=[],
        node=None,
        prev_stage="archive",
        curr_stage="runtime",
        active_layers=0,
        layers={},
        adaptive_learning=adaptive_learning,
        ordered_events=[],
    )


def test_stage1376_unavailable_rolling_weights_do_not_shift_log_odds_weighting() -> None:
    clean_score, clean_meta = _log_odds_with_learning({})
    failed_score, failed_meta = _log_odds_with_learning(
        {
            "rolling_learned_static": {
                "static_weight": 0.2,
                "learned_model_weight": 0.8,
                "unavailable_reason": "rolling_model_weight_replay_failed",
            }
        }
    )

    assert failed_score == clean_score
    assert failed_meta["static_weight"] == clean_meta["static_weight"]
    assert failed_meta["model_weight"] == clean_meta["model_weight"]


def test_stage1376_degraded_markov_metadata_cannot_inflate_model_probability() -> None:
    clean_score, clean_meta = _log_odds_with_learning({})
    degraded_score, degraded_meta = _log_odds_with_learning(
        {
            "markov": {
                "markov_anomaly": 1.0,
                "degraded": True,
            }
        }
    )

    assert degraded_score == clean_score
    assert degraded_meta["model_probability"] == clean_meta["model_probability"]
    assert degraded_meta["feature_probabilities"]["markov"] == 0.0
    assert degraded_meta["feature_probabilities"]["markov_unavailable_reason"] == "degraded_model_signal"


def test_stage1376_degraded_rolling_weights_do_not_override_recomputed_weights() -> None:
    clean_score, clean_meta = _log_odds_with_learning({})
    degraded_score, degraded_meta = _log_odds_with_learning(
        {
            "rolling_learned_static": {
                "static_weight": 0.2,
                "learned_model_weight": 0.8,
                "degraded": True,
            }
        }
    )

    assert degraded_score == clean_score
    assert degraded_meta["static_weight"] == clean_meta["static_weight"]
    assert degraded_meta["model_weight"] == clean_meta["model_weight"]
