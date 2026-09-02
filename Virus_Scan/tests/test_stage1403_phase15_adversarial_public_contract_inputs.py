"""Stage 1403: adversarial public model contract inputs stay evidence-backed."""

from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections.abc import Mapping

from Virus_Scan.models.api import (
    adaptive_signals,
    clustering_contracts,
    graph_contracts,
    markov_contracts,
    profile_contracts,
    profile_learning_contracts,
    replay_economics_contracts,
    replay_learning,
    temporal_contracts,
)


class ExplodingIterableAndString:
    def __iter__(self):
        raise TypeError("iteration unavailable")

    def __str__(self):
        raise RuntimeError("string unavailable")


def test_stage1403_markov_and_adaptive_public_contracts_absorb_adversarial_values() -> None:
    malformed = ExplodingIterableAndString()

    assert markov_contracts.canonical_behavior_flow(malformed) == ()

    pair = markov_contracts.markov_pair_probability(malformed, malformed)
    assert pair["ready"] is False
    assert pair["probability"] is None
    assert pair["reason"] == "malformed_markov_pair_public_input"

    stage = markov_contracts.markov_stage_probability(malformed, malformed, malformed)
    assert stage["ready"] is False
    assert stage["probability"] is None

    features = markov_contracts.compute_markov_features(malformed, malformed, malformed)
    assert features["ready"] is False
    assert features["flow"] == ()

    update = markov_contracts.update_markov_model(malformed, malformed, malformed, learning_decision=accepted_learning_decision(target_names=("markov",)))
    assert update["learned"] is False
    assert update["reason"] == "insufficient_behavior_flow"

    assert adaptive_signals.canonical_behavior_flow(malformed) == ()
    adaptive_graph = adaptive_signals.compute_graph_relationship_layer(
        malformed, tags=malformed,
    )
    assert adaptive_graph["graph_relationship_ready"] is False
    assert adaptive_graph["degraded"] is True


def test_stage1403_temporal_graph_cluster_profile_contracts_absorb_adversarial_values() -> None:
    malformed = ExplodingIterableAndString()

    snapshot = temporal_contracts.snapshot_temporal(malformed)
    assert snapshot["ready"] is False
    assert snapshot["degraded"] is True
    assert snapshot["unavailable_reason"] == "temporal_snapshot_public_input_invalid"

    overlay = temporal_contracts.transition_probability_overlay(
        prev_stage=malformed, tags=malformed, curr_stage=malformed, ordered_events=malformed
    )
    assert overlay["probability_ready"] is False
    assert overlay["final_json_must_record"] is True

    relationship = graph_contracts.compute_graph_relationship_layer(
        malformed, tags=malformed,
    )
    assert relationship["graph_relationship_ready"] is False
    assert relationship["replay_record_required"] is True
    assert graph_contracts.get_graph_risk_enhanced(malformed) == 0.0
    assert graph_contracts.link_archive_members_to_graph(malformed) == 0

    assignment = clustering_contracts.assign_cluster_with_context_tags(
        malformed, malformed, tags=malformed,
        learning_decision=accepted_learning_decision(target_names=("clustering",)),
    )
    assert assignment["assigned"] is False
    assert assignment["degraded"] is True
    assert clustering_contracts.load_cluster_runtime_model_record(malformed) is False

    profile = profile_contracts.default_engine_profile(malformed)
    assert profile["engine"] == "<ExplodingIterableAndString>"
    baseline = profile_contracts.get_extension_baseline(malformed, malformed)
    assert baseline["ready"] is False
    assert baseline["unavailable_reason"] == "extension_baseline_public_input_invalid"
    assert profile_contracts.validate_engine_profile_schema(malformed, expected_engine=malformed) is False


def test_stage1403_profile_and_replay_public_contracts_absorb_adversarial_values() -> None:
    malformed = ExplodingIterableAndString()

    flow = profile_learning_contracts.canonical_behavior_flow_from_sources(
        raw_tags=malformed,
        ordered_events=malformed,
        behavior_timeline=malformed,
        behavior_flow=malformed,
    )
    assert flow == []
    assert profile_learning_contracts.learning_verdict_is_clean(malformed) is False

    vector = profile_learning_contracts.behavior_vector_from_scan(
        malformed,
        malformed,
        malformed,
        api_calls=malformed,
        ordered_events=malformed,
    )
    assert vector["ready"] is False
    assert vector["degraded"] is True

    compressed = replay_economics_contracts.replay_compress_metadata(malformed)
    assert compressed == {
        "value": "<ExplodingIterableAndString>",
        "unavailable_reason": "unsupported_replay_metadata_type",
    }
    assert replay_economics_contracts.replay_should_retain(malformed) is True

    replay_result = replay_learning.persist_parent_learning_from_results(malformed)
    assert isinstance(replay_result, Mapping)
    assert replay_result["errors"] == 1
    assert replay_result["degraded"] is True
    assert replay_result["unavailable_reason"] == "parent_replay_results_iteration_failed"
