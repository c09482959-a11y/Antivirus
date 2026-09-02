"""Stage 1382 Phase 1 probability-feature readiness boundaries."""
from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from contextlib import ExitStack, contextmanager
from unittest.mock import patch


from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.adaptive import evidence_projection


@contextmanager
def _patch_clean_graph_temporal_engine():
    with ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_graph_risk_enhanced", lambda node: 0.0))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_graph_relationship_layer",
            lambda node, tags=None: {"ready": True, "score": 0.0, "hits": (), "propagated_chains": ()},
        ))
        stack.enter_context(patch.object(evidence_projection, "model_temporal_snapshot", lambda node: {"ready": True, "belief": 0.0}))
        stack.enter_context(patch.object(evidence_projection, "infer_engine_context", lambda tags, *, file_structure=None, strings_blob="": {"unity": 0.5}))
        stack.enter_context(patch.object(evidence_projection, "detect_evasion_signals", lambda tags, yara_hits, node: 0.0))
        stack.enter_context(patch.object(evidence_projection, "cluster_probability_feature", lambda node: (0.0, "cluster_not_assigned")))
        yield


def test_stage1382_not_ready_markov_without_reason_cannot_publish_probability() -> None:
    with _patch_clean_graph_temporal_engine(), ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_markov_features",
            lambda *args, **kwargs: {"ready": False, "transition": 0.95, "rarity": 0.95, "pair_anomaly": 0.95},
        ))
        stack.enter_context(patch.object(evidence_projection, "compute_attack_intelligence", lambda tags, yara_hits: {"aggregate_probability": 0.0, "ready": True, "degraded": False}))
        stack.enter_context(patch.object(evidence_projection, "model_extension_profile_anomaly", lambda *args, **kwargs: {"ready": True, "anomaly": 0.0}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"ready": True, "bucket_anomaly": 0.0},
                "vector_validation": {"ready": True, "anomaly": 0.0},
            },
        ))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1382-not-ready-markov.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec", "network_download"],
        )

        assert features["p_markov"] == 0.0
        assert features["p_markov_unavailable_reason"] == "model_signal_not_ready"


def test_stage1382_not_ready_profile_bucket_vector_without_reason_cannot_publish_probability() -> None:
    with _patch_clean_graph_temporal_engine(), ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(evidence_projection, "model_markov_features", lambda *args, **kwargs: {"ready": True, "transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0}))
        stack.enter_context(patch.object(evidence_projection, "compute_attack_intelligence", lambda tags, yara_hits: {"aggregate_probability": 0.0, "ready": True, "degraded": False}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_extension_profile_anomaly",
            lambda *args, **kwargs: {"ready": False, "anomaly": 0.95},
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"ready": False, "bucket_anomaly": 0.95},
                "vector_validation": {"ready": False, "anomaly": 0.95},
            },
        ))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1382-not-ready-profile-bucket-vector.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        assert features["p_profile"] == 0.0
        assert features["p_bucket"] == 0.0
        assert features["p_vector"] == 0.0
        assert features["p_profile_unavailable_reason"] == "model_signal_not_ready"
        assert features["p_bucket_unavailable_reason"] == "model_signal_not_ready"
        assert features["p_vector_unavailable_reason"] == "model_signal_not_ready"
        assert features["p_engine"] == 0.5


def test_stage1382_not_ready_attack_intelligence_without_reason_cannot_publish_static_probability() -> None:
    with _patch_clean_graph_temporal_engine(), ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(evidence_projection, "model_markov_features", lambda *args, **kwargs: {"ready": True, "transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0}))
        stack.enter_context(patch.object(evidence_projection, "compute_attack_intelligence", lambda tags, yara_hits: {"ready": False, "aggregate_probability": 0.95, "degraded": False}))
        stack.enter_context(patch.object(evidence_projection, "model_extension_profile_anomaly", lambda *args, **kwargs: {"ready": True, "anomaly": 0.0}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"ready": True, "bucket_anomaly": 0.0},
                "vector_validation": {"ready": True, "anomaly": 0.0},
            },
        ))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1382-not-ready-attack-intel.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        assert features["p_attack_intelligence"] == 0.0
        assert features["p_attack_intelligence_unavailable_reason"] == "attack_intelligence_not_ready"
        assert features["p_mitre"] == 0.0
        assert features["p_mitre_unavailable_reason"] == "mitre_official_mapping_unavailable"
        assert features["p_chain"] == 0.0
        assert features["p_chain_unavailable_reason"] is None


def test_stage1382_cluster_signal_ready_false_cannot_publish_adaptive_probability() -> None:
    probs = model_score.log_odds_feature_probabilities(model_score.LogOddsFeatureProbabilitiesRequest(
        {
            "p_yara": 0.0,
            "p_mitre": 0.0,
            "p_exec": 0.0,
            "p_behavior": 0.0,
            "p_evasion": 0.0,
            "p_entropy": 0.0,
            "p_profile": 0.0,
            "p_markov": 0.0,
            "p_temporal": 0.0,
            "p_cluster": 0.95,
            "p_bucket": 0.0,
            "p_vector": 0.0,
            "p_graph_chain": 0.0,
            "p_attention": 0.0,
            "p_graph": 0.0,
        },
        profile_meta={},
        markov_meta={},
        cluster_meta={"cluster_signal_ready": False, "cluster_signal": 1.0},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={},
    ))

    assert probs["p_cluster"] == 0.0
    assert probs["p_cluster_unavailable_reason"] == "model_signal_not_ready"
