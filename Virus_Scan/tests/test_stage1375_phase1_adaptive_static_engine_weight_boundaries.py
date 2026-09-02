"""Stage 1375 Phase 1 adaptive static/engine unavailable boundary repairs."""
from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from contextlib import ExitStack, contextmanager
from unittest.mock import patch


from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.adaptive import evidence_projection
from Virus_Scan.detection.scoring.adaptive import model_caps


def _base_feature_probs(**overrides):
    values = {
        "p_yara": 0.0,
        "p_attack_intelligence": 0.0,
        "p_mitre": 0.0,
        "p_chain": 0.0,
        "p_evasion": 0.0,
        "p_behavior": 0.0,
        "p_exec": 0.0,
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
    }
    values.update(overrides)
    return values


@contextmanager
def _patch_clean_probability_dependencies():
    with ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_graph_risk_enhanced", lambda node: 0.0))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_graph_relationship_layer",
            lambda node, tags=None: {"score": 0.0, "hits": (), "propagated_chains": ()},
        ))
        stack.enter_context(patch.object(evidence_projection, "model_temporal_snapshot", lambda node: {"ready": True, "belief": 0.0}))
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_markov_features",
            lambda prev_stage, behavior_flow, curr_stage: {"ready": True, "transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0},
        ))
        stack.enter_context(patch.object(evidence_projection, "compute_attack_intelligence", lambda tags, yara_hits: {"aggregate_probability": 0.0, "ready": True, "degraded": False}))
        stack.enter_context(patch.object(evidence_projection, "model_extension_profile_anomaly", lambda *args, **kwargs: {"anomaly": 0.0}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {"bucket_validation": {"bucket_anomaly": 0.0}, "vector_validation": {"anomaly": 0.0}},
        ))
        stack.enter_context(patch.object(evidence_projection, "cluster_probability_feature", lambda node: (0.0, None)))
        yield


def test_stage1375_partial_nonfinite_engine_context_does_not_publish_high_engine_probability() -> None:
    with _patch_clean_probability_dependencies(), ExitStack() as stack:
        stack.enter_context(patch.object(
            evidence_projection,
            "infer_engine_context",
            lambda tags, *, file_structure=None, strings_blob="": {"unity": float("inf"), "renpy": 0.88, "rpgm": float("nan")},
        ))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1375-partial-engine.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        assert features["p_engine"] == 0.0
        assert features["p_engine_unavailable_reason"] == "nonfinite_engine_context_probability"


def test_stage1375_hybrid_fusion_static_anchor_ignores_unavailable_chain_and_evasion() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(model_caps, "percentile_calibrate", lambda score: score))
        unavailable_static_high = _base_feature_probs(
            p_chain=1.0,
            p_evasion=1.0,
            p_profile=1.0,
            p_bucket=1.0,
            p_vector=1.0,
            p_chain_unavailable_reason="attack_chain_probability_failed",
            p_evasion_unavailable_reason="evasion_probability_failed",
        )
        zero_static_same_models = _base_feature_probs(
            p_profile=1.0,
            p_bucket=1.0,
            p_vector=1.0,
        )

        high_score = model_score.hybrid_static_model_evidence_fusion(unavailable_static_high)
        zero_score = model_score.hybrid_static_model_evidence_fusion(zero_static_same_models)

        assert high_score == zero_score
        assert unavailable_static_high["p_adaptive_learned_model_weight"] == zero_static_same_models["p_adaptive_learned_model_weight"]


def test_stage1375_adaptive_layer_weights_ignore_degraded_graph_and_intel_scores() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(
            model_caps,
            "model_adaptive_profile_signal",
            lambda *args, **kwargs: {
                "profile_ready": True,
                "profile_anomaly": 0.0,
                "files_seen": model_score.ADAPTIVE_WEIGHT_MIN_HISTORY,
                "engine": "unity",
            },
        ))
        stack.enter_context(patch.object(model_caps, "model_adaptive_markov_signal", lambda *args, **kwargs: {"markov_anomaly": 0.0}))
        stack.enter_context(patch.object(model_caps, "model_adaptive_cluster_signal", lambda *args, **kwargs: {"cluster_signal": 0.0}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"bucket_anomaly": 0.0},
                "vector_validation": {"anomaly": 0.0},
                "timeline_validation": {"anomaly": 0.0},
            },
        ))

        _weights, meta = model_score.learn_adaptive_layer_weights(
            node="stage1375-degraded-layer.exe",
            tags=[],
            
            quick={"score": 0.0},
            stage={"score": 0.0},
            graph={"score": 90.0, "degraded": True, "graph_unavailable_reason": "graph_layer_failed"},
            intel={"score": 90.0, "degraded": True, "unavailable_reason": "threat_intel_failed"},
            ordered_events=[],
        )

        assert meta["pre_rolling_weights"] == {
            "quick_static": 0.28,
            "stage_timeline": 0.22,
            "graph_relationships": 0.2,
            "threat_intel": 0.3,
        }
        assert meta["rolling_learned_static"]["static_anchor_score"] == 0.0
