from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from collections import Counter, defaultdict

from Virus_Scan.detection.scoring.adaptive.model_score import (
    build_probability_features,
    calibrated_log_odds_score_100,
)
from Virus_Scan.models.markov import adaptive_markov_signal, compute_markov_features
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.runtime.graph_state import reset_graph_state


def _reset_markov_state():
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_markov_cold_start_sequence_reports_support_and_reason():
    _reset_markov_state()

    features = compute_markov_features("asset", ["download", "exec"], "runtime")

    assert features["ready"] is False
    assert features["support"] == 0
    assert features["reason"] == "insufficient_markov_stage_support"
    assert features["transition"] == 0.0
    assert features["rarity"] == 0.0
    assert features["pair_anomaly"] == 0.0


def test_adaptive_markov_signal_preserves_cold_start_reason():
    _reset_markov_state()

    signal = adaptive_markov_signal("asset", "runtime", ["download", "exec"])

    assert signal["markov_ready"] is False
    assert signal["markov_support"] == 0
    assert signal["markov_unavailable_reason"] == "insufficient_markov_stage_support"
    assert signal["markov_anomaly"] == 0.0


def test_probability_features_publish_markov_unavailable_reason():
    _reset_markov_state()
    reset_graph_state()
    try:
        features = build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["download", "exec"],
            yara_hits=[],
            node="stage1143_markov_cold_start.exe",
            prev_stage="asset",
            curr_stage="runtime",
            ordered_events=["download", "exec"],
        )

        assert features["p_markov"] == 0.0
        assert features["p_markov_unavailable_reason"] == "insufficient_markov_stage_support"
    finally:
        reset_graph_state()


def test_log_odds_metadata_preserves_markov_unavailable_reason():
    _reset_markov_state()
    reset_graph_state()
    try:
        _score, meta = calibrated_log_odds_score_100(
            20.0,
            attack_mapping_result=unavailable_attack_mapping_fixture(),
            chain_evidence=adaptive_chain_evidence_fixture(tags=["download", "exec"], api_calls=None, ordered_events=["download", "exec"]),
            tags=["download", "exec"],
            yara_hits=[],
            node="stage1143_markov_cold_start_meta.exe",
            prev_stage="asset",
            curr_stage="runtime",
            ordered_events=["download", "exec"],
        )

        assert meta["feature_probabilities"]["markov"] == 0.0
        assert meta["feature_probabilities"]["markov_unavailable_reason"] == "insufficient_markov_stage_support"
    finally:
        reset_graph_state()
