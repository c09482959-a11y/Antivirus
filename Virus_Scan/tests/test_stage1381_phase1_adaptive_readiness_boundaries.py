"""Stage 1381 Phase 1 adaptive readiness availability boundaries."""
from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import LogOddsFeatureProbabilitiesRequest
from contextlib import ExitStack
from unittest.mock import patch


from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.adaptive import evidence_projection
from Virus_Scan.detection.scoring.adaptive import model_caps
from Virus_Scan.models.profiles import api as profiles
from Virus_Scan.models.profiles import adaptive_signal as profile_adaptive_signal
from Virus_Scan.models.profiles import coordinated_validation as profile_coordinated_validation
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.detection.scoring.adaptive.model_score import (
    availability_aware_layer_probability_summary,
    log_odds_feature_probabilities,
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


def _zero_model_signals() -> None:
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
        stack.enter_context(patch.object(model_caps, "model_adaptive_markov_signal", lambda *args, **kwargs: {"ready": True, "markov_anomaly": 0.0}))
        stack.enter_context(patch.object(model_caps, "model_adaptive_cluster_signal", lambda *args, **kwargs: {"ready": True, "cluster_signal": 0.0}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"ready": True, "bucket_anomaly": 0.0},
                "vector_validation": {"ready": True, "anomaly": 0.0},
                "timeline_validation": {"ready": True, "anomaly": 0.0},
            },
        ))


def test_stage1381_not_ready_adaptive_metadata_cannot_publish_probability() -> None:
    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        _base_feature_probs(
            p_profile=0.95,
            p_markov=0.95,
            p_temporal=0.95,
            p_cluster=0.95,
            p_bucket=0.95,
            p_vector=0.95,
        ),
        profile_meta={"profile_ready": False, "profile_anomaly": 1.0},
        markov_meta={"ready": False, "markov_anomaly": 1.0},
        cluster_meta={"ready": False, "cluster_signal": 1.0},
        bv_bucket={"ready": False, "bucket_anomaly": 1.0},
        bv_vector={"ready": False, "anomaly": 1.0},
        bv_timeline={"ready": False, "anomaly": 1.0},
        layer_probs={},
    ))

    assert probs["p_profile"] == 0.0
    assert probs["p_markov"] == 0.0
    assert probs["p_temporal"] == 0.0
    assert probs["p_cluster"] == 0.0
    assert probs["p_bucket"] == 0.0
    assert probs["p_vector"] == 0.0
    assert probs["p_profile_unavailable_reason"] == "model_signal_not_ready"
    assert probs["p_markov_unavailable_reason"] == "model_signal_not_ready"
    assert probs["p_temporal_unavailable_reason"] == "model_signal_not_ready"
    assert probs["p_cluster_unavailable_reason"] == "model_signal_not_ready"
    assert probs["p_bucket_unavailable_reason"] == "model_signal_not_ready"
    assert probs["p_vector_unavailable_reason"] == "model_signal_not_ready"


def test_stage1381_not_ready_layers_cannot_publish_layer_probabilities() -> None:
    summary = availability_aware_layer_probability_summary(
        {
            "graph": {"ready": False, "score": 100.0},
            "intel": {"ready": False, "score": 100.0},
            "stage": {"ready": False, "score": 100.0},
            "quick": {"ready": False, "score": 100.0},
        }
    )

    assert summary["graph_probability"] == 0.0
    assert summary["threat_intel_probability"] == 0.0
    assert summary["stage_probability"] == 0.0
    assert summary["quick_static_probability"] == 0.0
    assert summary["graph_unavailable_reason"] == "layer_probability_not_ready"
    assert summary["threat_intel_unavailable_reason"] == "layer_probability_not_ready"
    assert summary["stage_unavailable_reason"] == "layer_probability_not_ready"
    assert summary["quick_static_unavailable_reason"] == "layer_probability_not_ready"


def test_stage1381_not_ready_graph_relationship_layer_blocks_graph_chain_probability() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_graph_risk_enhanced", lambda node: 9.0))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_graph_relationship_layer",
            lambda node, tags=None: {
                "graph_relationship_ready": False,
                "score": 100.0,
                "hits": ("graph_hit",),
                "propagated_chains": ("chain_hit",),
            },
        ))
        stack.enter_context(patch.object(evidence_projection, "model_temporal_snapshot", lambda node: {"ready": True, "belief": 0.0}))
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(evidence_projection, "model_markov_features", lambda *args, **kwargs: {"ready": True, "transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0}))
        stack.enter_context(patch.object(evidence_projection, "compute_attack_intelligence", lambda tags, yara_hits: {"aggregate_probability": 0.0, "ready": True, "degraded": False}))
        stack.enter_context(patch.object(evidence_projection, "detect_evasion_signals", lambda tags, yara_hits, node: 0.0))
        stack.enter_context(patch.object(evidence_projection, "infer_engine_context", lambda tags, *, file_structure=None, strings_blob="": {"unity": 0.0}))
        stack.enter_context(patch.object(evidence_projection, "model_extension_profile_anomaly", lambda *args, **kwargs: {"anomaly": 0.0}))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"bucket_anomaly": 0.0},
                "vector_validation": {"anomaly": 0.0},
            },
        ))
        stack.enter_context(patch.object(evidence_projection, "cluster_probability_feature", lambda node: (0.0, "cluster_not_assigned")))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1381-not-ready-graph.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        assert features["p_graph"] == 0.0
        assert features["p_graph_chain"] == 0.0
        assert features["p_attention"] == 0.0
        assert features["p_graph_unavailable_reason"] == "graph_relationship_layer_not_ready"


def test_stage1381_not_ready_layer_scores_do_not_shift_adaptive_weights() -> None:
    _zero_model_signals()

    _weights, meta = model_score.learn_adaptive_layer_weights(
        node="stage1381-not-ready-layer.exe",
        tags=["process_exec", "network_download"],
        
        quick={"ready": False, "score": 100.0},
        stage={"ready": False, "score": 100.0},
        graph={"ready": False, "score": 100.0},
        intel={"ready": False, "score": 100.0},
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
        "quick_static": "layer_weight_signal_not_ready",
        "stage_timeline": "layer_weight_signal_not_ready",
        "graph_relationships": "layer_weight_signal_not_ready",
        "threat_intel": "layer_weight_signal_not_ready",
    }


def test_stage1381_profile_coordinated_validation_zeroes_not_ready_support() -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(
            profile_coordinated_validation,
            "get_extension_baseline",
            lambda engine, file_path: default_extension_baseline(".exe"),
        ))
        stack.enter_context(patch.object(profile_coordinated_validation, "profile_behavior_bucket_validation", lambda *args, **kwargs: {"bucket_anomaly": 0.0, "filetype_validation": {"filetype_anomaly": 0.0}}))
        stack.enter_context(patch.object(profile_coordinated_validation, "behavior_vector_from_scan", lambda *args, **kwargs: {}))
        stack.enter_context(patch.object(profile_coordinated_validation, "vector_baseline_anomaly", lambda *args, **kwargs: {"anomaly": 0.0}))
        stack.enter_context(patch.object(profile_coordinated_validation, "extension_timeline_anomaly", lambda *args, **kwargs: {"anomaly": 0.0}))
        stack.enter_context(patch.object(
            profile_coordinated_validation,
            "snapshot_temporal",
            lambda file_path: {"ready": False, "belief": 1.0, "unavailable_reason": "temporal_cold_start"},
        ))
        stack.enter_context(patch.object(
            profile_coordinated_validation,
            "compute_markov_features",
            lambda *args, **kwargs: {
                "ready": False,
                "transition": 1.0,
                "rarity": 1.0,
                "pair_anomaly": 1.0,
                "reason": "markov_cold_start",
            },
        ))

        result = profiles.coordinated_model_validation_signal(
            "unity",
            "stage1381-not-ready-profile.exe",
            ["process_exec"],
            ordered_events=["process_exec", "network_download"],
        )

        assert result["model_anomaly"] == 0.0
        assert result["temporal_support"] == 0.0
        assert result["markov_support"] == 0.0
        assert result["degraded"] is True
        assert result["unavailable_reasons"]["temporal_support"] == "temporal_cold_start"
        assert result["unavailable_reasons"]["markov_support"] == "markov_cold_start"
        assert result["final_json_must_record"] is True
        assert result["replay_record_required"] is True
