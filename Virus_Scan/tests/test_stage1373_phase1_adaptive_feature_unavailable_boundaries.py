"""Stage 1373 Phase 1 adaptive feature-probability availability boundaries."""
from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import LogOddsFeatureProbabilitiesRequest
from contextlib import ExitStack
from unittest.mock import patch


from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.adaptive import evidence_projection
from Virus_Scan.detection.scoring.adaptive import model_caps
from Virus_Scan.detection.scoring.adaptive.model_score import log_odds_feature_probabilities


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


def test_stage1373_unavailable_feature_probabilities_cannot_inflate_log_odds_model_side() -> None:
    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        _base_feature_probs(
            p_profile=0.95,
            p_markov=0.95,
            p_temporal=0.95,
            p_cluster=0.95,
            p_bucket=0.95,
            p_vector=0.95,
            p_graph=0.95,
            p_graph_chain=0.95,
            p_attention=0.95,
            p_profile_unavailable_reason="profile_unavailable",
            p_markov_unavailable_reason="markov_cold_start",
            p_temporal_unavailable_reason="temporal_not_ready",
            p_cluster_unavailable_reason="cluster_not_assigned",
            p_bucket_unavailable_reason="bucket_unavailable",
            p_vector_unavailable_reason="vector_unavailable",
            p_graph_unavailable_reason="graph_unavailable",
            p_graph_chain_unavailable_reason="graph_chain_unavailable",
        ),
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={"graph_probability": 0.95},
    ))

    assert probs["p_profile"] == 0.0
    assert probs["p_markov"] == 0.0
    assert probs["p_temporal"] == 0.0
    assert probs["p_cluster"] == 0.0
    assert probs["p_bucket"] == 0.0
    assert probs["p_vector"] == 0.0
    assert probs["p_graph"] == 0.0
    assert probs["p_graph_chain"] == 0.0
    assert probs["p_attention"] == 0.0
    assert probs["p_profile_unavailable_reason"] == "profile_unavailable"
    assert probs["p_markov_unavailable_reason"] == "markov_cold_start"
    assert probs["p_temporal_unavailable_reason"] == "temporal_not_ready"
    assert probs["p_cluster_unavailable_reason"] == "cluster_not_assigned"
    assert probs["p_bucket_unavailable_reason"] == "bucket_unavailable"
    assert probs["p_vector_unavailable_reason"] == "vector_unavailable"
    assert probs["p_graph_unavailable_reason"] == "graph_unavailable"


def test_stage1373_clean_feature_probabilities_still_flow_to_log_odds_model_side() -> None:
    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        _base_feature_probs(
            p_profile=0.11,
            p_markov=0.22,
            p_temporal=0.33,
            p_cluster=0.44,
            p_bucket=0.55,
            p_vector=0.66,
            p_graph=0.12,
            p_graph_chain=0.77,
            p_attention=0.88,
        ),
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={"graph_probability": 0.45},
    ))

    assert probs["p_profile"] == 0.11
    assert probs["p_markov"] == 0.22
    assert probs["p_temporal"] == 0.33
    assert probs["p_cluster"] == 0.44
    assert probs["p_bucket"] == 0.55
    assert probs["p_vector"] == 0.66
    assert probs["p_graph"] == 0.45
    assert probs["p_graph_chain"] == 0.77
    assert probs["p_attention"] == 0.88


def test_stage1373_build_probability_features_zeroes_unavailable_model_probabilities() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_graph_risk_enhanced", lambda node: 9.0))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_graph_relationship_layer",
            lambda node, tags=None: {
                "score": 80.0,
                "hits": ("graph_hit",),
                "propagated_chains": (),
                "graph_unavailable_reason": "graph_snapshot_unavailable",
            },
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_temporal_snapshot",
            lambda node: {"ready": False, "belief": 0.9, "unavailable_reason": "temporal_not_ready"},
        ))
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_markov_features",
            lambda prev_stage, behavior_flow, curr_stage: {
                "ready": False,
                "reason": "insufficient_markov_support",
                "transition": 0.9,
                "rarity": 0.9,
                "pair_anomaly": 0.9,
            },
        ))
        stack.enter_context(patch.object(evidence_projection, "infer_engine_context", lambda tags, *, file_structure=None, strings_blob="": {"unity": 0.8}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_extension_profile_anomaly",
            lambda *args, **kwargs: {"anomaly": 0.9, "reason": "profile_unavailable"},
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"bucket_anomaly": 0.9, "reason": "bucket_unavailable"},
                "vector_validation": {"anomaly": 0.9, "reason": "vector_unavailable"},
            },
        ))
        stack.enter_context(patch.object(evidence_projection, "cluster_probability_feature", lambda node: (0.9, "cluster_not_assigned")))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1373-unavailable.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec", "network_download"],
        )

        assert features["p_graph"] == 0.0
        assert features["p_graph_chain"] == 0.0
        assert features["p_attention"] == 0.0
        assert features["p_temporal"] == 0.0
        assert features["p_markov"] == 0.0
        assert features["p_profile"] == 0.0
        assert features["p_bucket"] == 0.0
        assert features["p_vector"] == 0.0
        assert features["p_cluster"] == 0.0
        assert features["p_engine"] == 0.8
        assert features["p_graph_unavailable_reason"] == "graph_snapshot_unavailable"
        assert features["p_temporal_unavailable_reason"] == "temporal_not_ready"
        assert features["p_markov_unavailable_reason"] == "insufficient_markov_support"
        assert features["p_profile_unavailable_reason"] == "profile_unavailable"
        assert features["p_bucket_unavailable_reason"] == "bucket_unavailable"
        assert features["p_vector_unavailable_reason"] == "vector_unavailable"
        assert features["p_cluster_unavailable_reason"] == "cluster_not_assigned"


def test_stage1373_hybrid_fusion_confidence_ignores_unavailable_model_feature_values() -> None:
    features = _base_feature_probs(
        p_yara=0.0,
        p_chain=0.0,
        p_exec=0.0,
        p_behavior=0.0,
        p_profile=1.0,
        p_markov=1.0,
        p_temporal=1.0,
        p_cluster=1.0,
        p_bucket=1.0,
        p_vector=1.0,
        p_attention=1.0,
        p_profile_unavailable_reason="profile_unavailable",
        p_markov_unavailable_reason="markov_unavailable",
        p_temporal_unavailable_reason="temporal_unavailable",
        p_cluster_unavailable_reason="cluster_unavailable",
        p_bucket_unavailable_reason="bucket_unavailable",
        p_vector_unavailable_reason="vector_unavailable",
        p_graph_unavailable_reason="graph_unavailable",
    )

    model_score.hybrid_static_model_evidence_fusion(features)

    assert features["p_adaptive_learned_model_confidence"] == 0.0


def test_stage1373_adaptive_layer_weight_learning_ignores_unavailable_model_shift_signals() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(
            model_caps,
            "model_adaptive_profile_signal",
            lambda *args, **kwargs: {
                "profile_ready": True,
                "profile_anomaly": 1.0,
                "reason": "profile_unavailable",
                "files_seen": model_score.ADAPTIVE_WEIGHT_MIN_HISTORY,
                "engine": "unity",
            },
        ))
        stack.enter_context(patch.object(
            model_caps,
            "model_adaptive_markov_signal",
            lambda *args, **kwargs: {"markov_anomaly": 1.0, "markov_unavailable_reason": "markov_cold_start"},
        ))
        stack.enter_context(patch.object(
            model_caps,
            "model_adaptive_cluster_signal",
            lambda *args, **kwargs: {"cluster_signal": 1.0, "cluster_unavailable_reason": "cluster_not_assigned"},
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"bucket_anomaly": 1.0, "reason": "bucket_unavailable"},
                "vector_validation": {"anomaly": 1.0, "reason": "vector_unavailable"},
                "timeline_validation": {"anomaly": 1.0, "reason": "timeline_unavailable"},
            },
        ))

        _weights, meta = model_score.learn_adaptive_layer_weights(
            node="stage1373-node.exe",
            tags=[],
            
            quick={"score": 0.0},
            stage={"score": 0.0},
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
        assert meta["rolling_learned_static"]["model_confidence"] == 0.0


def test_stage1373_hybrid_fusion_score_ignores_unavailable_model_feature_values() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(model_caps, "percentile_calibrate", lambda score: score))
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
            p_profile_unavailable_reason="profile_unavailable",
            p_markov_unavailable_reason="markov_unavailable",
            p_temporal_unavailable_reason="temporal_unavailable",
            p_cluster_unavailable_reason="cluster_unavailable",
            p_bucket_unavailable_reason="bucket_unavailable",
            p_vector_unavailable_reason="vector_unavailable",
            p_graph_unavailable_reason="graph_unavailable",
            p_graph_chain_unavailable_reason="graph_chain_unavailable",
        )
        zero_models = _base_feature_probs()

        high_score = model_score.hybrid_static_model_evidence_fusion(unavailable_high)
        zero_score = model_score.hybrid_static_model_evidence_fusion(zero_models)

        assert high_score == zero_score
        assert unavailable_high["p_adaptive_learned_model_confidence"] == 0.0
