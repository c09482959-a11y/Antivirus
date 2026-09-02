"""Stage 1374 Phase 1 adaptive static/model unavailable probability boundaries."""
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


def test_stage1374_partial_attack_intelligence_degradation_preserves_independent_probability() -> None:
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
        stack.enter_context(patch.object(evidence_projection, "compute_attack_intelligence", lambda tags, yara_hits: {"aggregate_probability": 0.95, "ready": True, "degraded": True}))
        stack.enter_context(patch.object(evidence_projection, "infer_engine_context", lambda tags, *, file_structure=None, strings_blob="": {"unity": 0.0}))
        stack.enter_context(patch.object(evidence_projection, "model_extension_profile_anomaly", lambda *args, **kwargs: {"anomaly": 0.0}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {"bucket_validation": {"bucket_anomaly": 0.0}, "vector_validation": {"anomaly": 0.0}},
        ))
        stack.enter_context(patch.object(evidence_projection, "cluster_probability_feature", lambda node: (0.0, None)))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1374-degraded-attack.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        assert features["p_attack_intelligence"] == 0.95
        assert features["p_attack_intelligence_unavailable_reason"] is None
        assert features["p_mitre"] == 0.0
        assert features["p_mitre_unavailable_reason"] == "mitre_official_mapping_unavailable"
        assert features["p_chain"] == 0.0
        assert features["p_chain_unavailable_reason"] is None


def test_stage1374_log_odds_ignores_unavailable_mitre_feature_probability() -> None:
    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        _base_feature_probs(
            p_attack_intelligence=0.95,
            p_evasion=0.95,
            p_attack_intelligence_unavailable_reason="attack_intelligence_degraded",
            p_evasion_unavailable_reason="evasion_probability_failed",
        ),
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={},
    ))

    assert probs["p_attack_intelligence"] == 0.0
    assert probs["p_evasion"] == 0.0
    assert probs["p_attack_intelligence_unavailable_reason"] == "attack_intelligence_degraded"
    assert probs["p_evasion_unavailable_reason"] == "evasion_probability_failed"


def test_stage1374_hybrid_fusion_ignores_unavailable_static_context_probabilities() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(model_caps, "percentile_calibrate", lambda score: score))
        unavailable_high = _base_feature_probs(
            p_engine=1.0,
            p_attack_intelligence=1.0,
            p_mitre=1.0,
            p_chain=1.0,
            p_evasion=1.0,
            p_engine_unavailable_reason="nonfinite_engine_context_probability",
            p_attack_intelligence_unavailable_reason="attack_intelligence_degraded",
            p_mitre_unavailable_reason="mitre_official_mapping_unavailable",
            p_chain_unavailable_reason="chain_evidence_degraded",
            p_evasion_unavailable_reason="evasion_probability_failed",
        )
        zero_features = _base_feature_probs()

        high_score = model_score.hybrid_static_model_evidence_fusion(unavailable_high)
        zero_score = model_score.hybrid_static_model_evidence_fusion(zero_features)

        assert high_score == zero_score
