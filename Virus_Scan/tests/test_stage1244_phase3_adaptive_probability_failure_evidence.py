from __future__ import annotations
from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence

from collections.abc import Mapping

from Virus_Scan.detection.scoring.adaptive.model_score import (
    build_probability_features,
    calibrated_log_odds_score_100,
)
from Virus_Scan.models.contracts.model_feature_bundle import materialize_model_feature_bundle
from Virus_Scan.runtime.graph_state import reset_graph_state


class _BadEvasionNode:
    str_calls = 0

    def __str__(self) -> str:  # pragma: no cover - must not be invoked
        type(self).str_calls += 1
        raise AssertionError("caller-owned node __str__ invoked")

    def __getattribute__(self, name: str):
        if name in {"edges", "neighbors", "links"}:
            raise ValueError("evasion node relationship probe failed")
        return object.__getattribute__(self, name)


def test_stage1244_evasion_probability_failure_has_explicit_immutable_evidence() -> None:
    reset_graph_state()
    _BadEvasionNode.str_calls = 0
    try:
        features = build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node=_BadEvasionNode(),
            prev_stage="binary",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        assert isinstance(features, Mapping)
        assert not isinstance(features, dict)
        assert features["p_evasion"] == 0.0
        assert features["p_evasion_unavailable_reason"] == "adaptive_probability_node_coercion_failed"
        assert _BadEvasionNode.str_calls == 0

        materialized = materialize_model_feature_bundle(features)
        assert materialized["p_evasion_unavailable_reason"] == "adaptive_probability_node_coercion_failed"
        assert tuple(materialized) == tuple(sorted(materialized))
    finally:
        reset_graph_state()


def test_stage1244_log_odds_metadata_preserves_evasion_failure_evidence() -> None:
    reset_graph_state()
    _BadEvasionNode.str_calls = 0
    try:
        _score, meta = calibrated_log_odds_score_100(
            20.0,
            attack_mapping_result=unavailable_attack_mapping_fixture(),
            chain_evidence=adaptive_chain_evidence_fixture(tags=["process_exec"], api_calls=None, ordered_events=["process_exec"]),
            tags=["process_exec"],
            yara_hits=[],
            node=_BadEvasionNode(),
            prev_stage="binary",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        features = meta["feature_probabilities"]
        assert features["evasion"] == 0.0
        assert features["evasion_unavailable_reason"] == "adaptive_probability_node_coercion_failed"
        assert _BadEvasionNode.str_calls == 0
        assert "mitre_unavailable_reason" in features
        assert "chain_unavailable_reason" in features
    finally:
        reset_graph_state()
