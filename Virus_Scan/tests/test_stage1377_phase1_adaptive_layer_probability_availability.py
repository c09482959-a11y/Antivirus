"""Stage 1377 Phase 1 adaptive layer-probability availability boundaries."""
from __future__ import annotations
from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import LogOddsFeatureProbabilitiesRequest

from Virus_Scan.detection.scoring.adaptive.model_score import (
    availability_aware_layer_probability_summary,
    log_odds_feature_probabilities,
    calibrated_log_odds_score_100,
)


def _base_feature_probs(**overrides):
    values = {
        "p_yara": 0.0,
        "p_mitre": 0.0,
        "p_exec": 0.0,
        "p_behavior": 0.0,
        "p_evasion": 0.0,
        "p_entropy": 0.0,
        "p_profile": 0.0,
        "p_markov": 0.0,
        "p_temporal": 0.0,
        "p_cluster": 0.0,
        "p_bucket": 0.0,
        "p_vector": 0.0,
        "p_graph_chain": 0.0,
        "p_attention": 0.0,
        "p_graph": 0.0,
    }
    values.update(overrides)
    return values


def test_stage1377_unavailable_graph_layer_probability_cannot_inflate_log_odds_graph_model() -> None:
    layer_probs = availability_aware_layer_probability_summary(
        {"graph": {"score": 100.0, "graph_unavailable_reason": "graph_snapshot_unavailable"}}
    )

    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        _base_feature_probs(p_graph=0.0),
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs=layer_probs,
    ))

    assert layer_probs["graph_probability"] == 0.0
    assert layer_probs["graph_unavailable_reason"] == "graph_snapshot_unavailable"
    assert probs["p_graph"] == 0.0
    assert probs["p_graph_unavailable_reason"] == "graph_snapshot_unavailable"


def test_stage1377_clean_graph_layer_probability_still_flows_to_log_odds_graph_model() -> None:
    layer_probs = availability_aware_layer_probability_summary({"graph": {"score": 100.0}})

    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        _base_feature_probs(p_graph=0.0),
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs=layer_probs,
    ))

    assert layer_probs["graph_probability"] > 0.9
    assert probs["p_graph"] > 0.9
    assert probs.get("p_graph_unavailable_reason") is None


def test_stage1377_unavailable_threat_intel_layer_probability_cannot_inflate_static_probability() -> None:
    unavailable_score, unavailable_meta = calibrated_log_odds_score_100(
        0.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        node=None,
        layers={"intel": {"score": 100.0, "threat_intel_unavailable_reason": "intel_snapshot_unavailable"}},
    )
    clean_high_score, clean_high_meta = calibrated_log_odds_score_100(
        0.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        node=None,
        layers={"intel": {"score": 100.0}},
    )

    assert unavailable_meta["static_probability"] < clean_high_meta["static_probability"]
    assert unavailable_score < clean_high_score
    assert unavailable_meta["layer_probability_unavailable_reasons"] == {
        "threat_intel": "intel_snapshot_unavailable"
    }


def test_stage1377_unavailable_quick_static_layer_probability_cannot_inflate_static_probability() -> None:
    unavailable_score, unavailable_meta = calibrated_log_odds_score_100(
        0.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        node=None,
        layers={"quick": {"score": 100.0, "unavailable_reason": "quick_static_failed"}},
    )
    clean_high_score, clean_high_meta = calibrated_log_odds_score_100(
        0.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        node=None,
        layers={"quick": {"score": 100.0}},
    )

    assert unavailable_meta["static_probability"] < clean_high_meta["static_probability"]
    assert unavailable_score < clean_high_score
    assert unavailable_meta["layer_probability_unavailable_reasons"] == {
        "quick_static": "quick_static_failed"
    }
