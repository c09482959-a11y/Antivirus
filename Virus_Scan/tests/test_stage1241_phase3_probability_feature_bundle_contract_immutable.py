from __future__ import annotations
from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence

from collections.abc import Mapping

import pytest

from Virus_Scan.detection.scoring.adaptive.model_score import (
    build_probability_features,
    calibrated_log_odds_score_100,
)
from Virus_Scan.models.contracts.model_feature_bundle import materialize_model_feature_bundle
from Virus_Scan.runtime.graph_state import reset_graph_state


def test_stage1241_probability_features_are_immutable_model_feature_bundle() -> None:
    reset_graph_state()

    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=["process_exec", "cmd_exec"],
        yara_hits=[],
        node=None,
        prev_stage="asset",
        curr_stage="runtime",
        ordered_events=["process_exec", "cmd_exec"],
    )

    assert isinstance(features, Mapping)
    assert not isinstance(features, dict)
    assert features["model_version"] == "adaptive_probability_features_v2"
    assert features["p_graph_unavailable_reason"] == "graph_node_not_provided"
    assert features["p_cluster_unavailable_reason"] == "cluster_node_not_provided"
    assert features["p_temporal_unavailable_reason"] == "temporal_node_not_provided"
    with pytest.raises(TypeError):
        features["p_markov"] = 1.0


def test_stage1241_probability_features_materialize_deterministically() -> None:
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=["cmd_exec", "process_exec"],
        yara_hits=[],
        node=None,
        prev_stage="asset",
        curr_stage="runtime",
        ordered_events=["cmd_exec", "process_exec"],
    )

    first = materialize_model_feature_bundle(features)
    second = materialize_model_feature_bundle(features)

    assert first == second
    assert tuple(first) == tuple(sorted(first))
    assert first["model_version"] == "adaptive_probability_features_v2"


def test_stage1241_log_odds_consumes_immutableprobability_feature_bundle() -> None:
    reset_graph_state()

    _score, meta = calibrated_log_odds_score_100(
        25.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=["contextual_identity"], api_calls=None, ordered_events=[]),
        tags=["contextual_identity"],
        yara_hits=[],
        node=None,
        prev_stage="unknown",
        curr_stage="unknown",
        ordered_events=[],
    )

    feature_meta = meta["feature_probabilities"]
    assert feature_meta["graph_unavailable_reason"] == "graph_node_not_provided"
    assert feature_meta["cluster_unavailable_reason"] == "cluster_node_not_provided"
    assert feature_meta["temporal_unavailable_reason"] == "temporal_node_not_provided"
    assert 0.0 <= feature_meta["markov"] <= 1.0
