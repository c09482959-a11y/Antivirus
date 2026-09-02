"""Stage 1402: public model contracts emit degraded evidence for malformed input."""

from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models.api import clustering_contracts, graph_contracts, profile_contracts, temporal_contracts
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


class NonIterableInput:
    pass


def test_stage1402_temporal_public_contracts_report_malformed_sequences() -> None:
    malformed = NonIterableInput()

    validation = temporal_contracts.compute_temporal_validation(
        "node", tags=malformed, prev_stage="prev", curr_stage="curr"
    )
    assert isinstance(validation, Mapping)
    assert validation["ready"] is False
    assert validation["degraded"] is True
    assert validation["unavailable_reason"] == "non_iterable_temporal_public_sequence"
    assert validation["final_json_must_record"] is True
    assert validation["replay_record_required"] is True

    overlay = temporal_contracts.transition_probability_overlay(
        prev_stage="prev", tags=malformed, curr_stage="curr", ordered_events=malformed
    )
    assert overlay["probability_ready"] is False
    assert overlay["stage_probability"] is None
    assert overlay["degraded"] is True
    assert overlay["unavailable_reason"] == "non_iterable_temporal_public_sequence"
    assert overlay["final_json_must_record"] is True

    update = temporal_contracts.update_temporal("node", "stage", malformed, learning_decision=accepted_learning_decision(target_names=("temporal",)))
    assert update["updated"] is False
    assert update["degraded"] is True
    assert update["unavailable_reason"] == "non_iterable_temporal_public_sequence"
    assert update["replay_record_required"] is True


def test_stage1402_graph_public_contracts_report_malformed_sequences_and_paths() -> None:
    malformed = NonIterableInput()

    relationship = graph_contracts.compute_graph_relationship_layer(
        "node", tags=malformed,
    )
    assert relationship["graph_relationship_ready"] is False
    assert relationship["degraded"] is True
    assert relationship["graph_unavailable_reason"] == "non_iterable_graph_public_sequence"
    assert relationship["final_json_must_record"] is True
    assert relationship["replay_record_required"] is True

    temporal_link = graph_contracts.link_temporal_to_graph("node", "prev", malformed, "curr")
    assert temporal_link["linked"] is False
    assert temporal_link["degraded"] is True
    assert temporal_link["unavailable_reason"] == "non_iterable_graph_public_sequence"

    assert graph_contracts.scan_cs(malformed) == ["graph_cs_scan_unavailable"]


def test_stage1402_clustering_public_contracts_report_malformed_vectors() -> None:
    malformed = NonIterableInput()

    assignment = clustering_contracts.assign_cluster_with_context_tags(
        "node", malformed, tags=malformed, engine_context=malformed,
        learning_decision=accepted_learning_decision(target_names=("clustering",)),
    )
    assert assignment["assigned"] is False
    assert assignment["degraded"] is True
    assert assignment["cluster_unavailable_reason"] == "invalid_cluster_vector_sequence"
    assert assignment["final_json_must_record"] is True

    update = clustering_contracts.online_vector_update(malformed, malformed, malformed)
    assert update["updated"] is False
    assert update["degraded"] is True
    assert update["unavailable_reason"] == "invalid_cluster_vector_sequence"
    assert update["replay_record_required"] is True


def test_stage1402_profile_public_contracts_do_not_leak_opaque_objects() -> None:
    profile = profile_contracts.default_engine_profile(NonIterableInput())

    assert isinstance(profile["engine"], str)
    assert "NonIterableInput" in profile["engine"]

from Virus_Scan.models.api import profile_learning_contracts, profile_retention_contracts


def test_stage1402_profile_learning_public_contracts_report_malformed_sequences() -> None:
    malformed = NonIterableInput()

    commit = profile_learning_contracts.commit_promoted_learning(
        malformed,
        malformed,
        malformed,
        api_calls=malformed,
        ordered_events=malformed,
        behavior_flow=malformed,
        verdict="clean",
    )
    assert commit["learned"] is False
    assert commit["degraded"] is True
    assert commit["unavailable_reason"] == "non_iterable_profile_learning_public_sequence"
    assert commit["final_json_must_record"] is True
    assert commit["replay_record_required"] is True

    assert not hasattr(profile_learning_contracts, "update_filetype")

    vector = profile_learning_contracts.behavior_vector_from_scan(
        malformed, malformed, malformed, api_calls=malformed, ordered_events=malformed
    )
    assert vector["ready"] is False
    assert vector["evidence_type"] == "profile_behavior_vector"
    assert vector["unavailable_reason"] == "non_iterable_profile_learning_public_sequence"


def test_stage1402_profile_retention_public_contracts_report_non_mapping_inputs() -> None:
    malformed = NonIterableInput()

    profile = profile_retention_contracts.prune_engine_profile_for_retention(malformed)
    assert profile["ready"] is False
    assert profile["degraded"] is True
    assert profile["unavailable_reason"] == "non_mapping_engine_profile_retention_input"
    assert profile["final_json_must_record"] is True

    baseline = profile_retention_contracts.prune_extension_baseline_for_retention(malformed)
    assert baseline["ready"] is False
    assert baseline["unavailable_reason"] == "non_mapping_extension_baseline_retention_input"

    staged = profile_retention_contracts.prune_staged_benign_store(malformed)
    assert staged["ready"] is False
    assert staged["unavailable_reason"] == "non_mapping_staged_benign_retention_input"
