"""Stage 1384 Phase 1 replayed probability-feature readiness boundaries."""
from __future__ import annotations

from unittest.mock import patch

from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.adaptive import model_caps


def _base_feature_probs(**overrides):
    values = {
        "p_yara": 0.0,
        "p_attack_intelligence": 0.0,
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
        "p_engine": 0.0,
        "p_chain": 0.0,
    }
    values.update(overrides)
    return values


def test_stage1384_replayed_not_ready_feature_probabilities_do_not_publish_log_odds_support() -> None:
    probs = model_score.log_odds_feature_probabilities(model_score.LogOddsFeatureProbabilitiesRequest(
        _base_feature_probs(
            p_markov=0.95,
            p_profile=0.95,
            p_bucket=0.95,
            p_vector=0.95,
            p_temporal=0.95,
            p_cluster=0.95,
            p_graph=0.95,
            p_graph_chain=0.95,
            p_attention=0.95,
            p_markov_ready=False,
            p_profile_ready=False,
            p_bucket_ready=False,
            p_vector_ready=False,
            p_temporal_ready=False,
            p_cluster_ready=False,
            graph_relationship_ready=False,
        ),
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={},
    ))

    assert probs["p_markov"] == 0.0
    assert probs["p_profile"] == 0.0
    assert probs["p_bucket"] == 0.0
    assert probs["p_vector"] == 0.0
    assert probs["p_temporal"] == 0.0
    assert probs["p_cluster"] == 0.0
    assert probs["p_graph"] == 0.0
    assert probs["p_graph_chain"] == 0.0
    assert probs["p_attention"] == 0.0
    assert probs["p_markov_unavailable_reason"] == "markov_probability_not_ready"
    assert probs["p_profile_unavailable_reason"] == "profile_probability_not_ready"
    assert probs["p_bucket_unavailable_reason"] == "bucket_probability_not_ready"
    assert probs["p_vector_unavailable_reason"] == "vector_probability_not_ready"
    assert probs["p_temporal_unavailable_reason"] == "temporal_probability_not_ready"
    assert probs["p_cluster_unavailable_reason"] == "cluster_probability_not_ready"
    assert probs["p_graph_unavailable_reason"] == "graph_probability_not_ready"


def test_stage1384_hybrid_fusion_ignores_replayed_not_ready_probability_features() -> None:
    with patch.object(model_caps, "percentile_calibrate", lambda score: score):
        unavailable_high = _base_feature_probs(
        p_profile=1.0,
        p_markov=1.0,
        p_temporal=1.0,
        p_cluster=1.0,
        p_bucket=1.0,
        p_vector=1.0,
        p_graph=1.0,
        p_graph_chain=1.0,
        p_attention=1.0,
        p_attack_intelligence=1.0,
        p_mitre=1.0,
        p_chain=1.0,
        p_evasion=1.0,
        p_markov_ready=False,
        p_profile_ready=False,
        p_bucket_ready=False,
        p_vector_ready=False,
        p_temporal_ready=False,
        p_cluster_ready=False,
        graph_relationship_ready=False,
        attack_intelligence_ready=False,
        mitre_ready=False,
        chain_ready=False,
        p_evasion_ready=False,
    )
        zero_features = _base_feature_probs()

        high_score = model_score.hybrid_static_model_evidence_fusion(unavailable_high)
        zero_score = model_score.hybrid_static_model_evidence_fusion(zero_features)

        assert high_score == zero_score
        assert unavailable_high["p_adaptive_learned_model_confidence"] == 0.0
        assert unavailable_high["p_adaptive_learned_model_weight"] == zero_features["p_adaptive_learned_model_weight"]
        assert unavailable_high["p_attack_intelligence_unavailable_reason"] == "attack_intelligence_probability_not_ready"
        assert unavailable_high["p_mitre_unavailable_reason"] == "mitre_probability_not_ready"
        assert unavailable_high["p_chain_unavailable_reason"] == "chain_probability_not_ready"
        assert unavailable_high["p_evasion_unavailable_reason"] == "evasion_probability_not_ready"
