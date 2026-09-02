from __future__ import annotations

from collections import Counter, defaultdict

import pytest

from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.models import markov, temporal
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_model_mapping_snapshot,
)
from Virus_Scan.runtime.temporal_state import temporal_history_snapshot
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def _reset_markov_state():
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage948_markov_and_temporal_model_modules_are_canonical_public_contracts():
    assert callable(markov.compute_markov_features)
    assert callable(markov.update_markov_model)
    assert callable(markov.canonical_behavior_flow)
    assert callable(temporal.update_temporal)
    assert callable(temporal.snapshot_temporal)
    assert callable(temporal.transition_probability_overlay)


def test_stage948_markov_canonical_behavior_flow_normalizes_dicts_prefixes_and_duplicates():
    flow = markov.canonical_behavior_flow([
        " API_LoadURL ", {"tag": "api_loadurl"},
        {"behavior": "tag_process_spawn"}, {"event": "network_download"},
        {"raw": "network_download"}, "", None,
    ])
    assert flow == ("loadurl", "process_spawn", "network_download")


def test_stage948_markov_update_learns_sequence_and_pair_counts_through_runtime_owner():
    _reset_markov_state()
    flow = ["download", "exec"]
    for index in range(3):
        result = markov.update_markov_model(
            "asset", flow, "runtime",
            learning_decision=accepted_learning_decision(
                target_names=("markov",), observation_id=f"stage948-markov-{index}",
            ),
        )
        assert result["learned"] is True
        assert result["flow"] == tuple(flow)
        assert result["transitions"] == 1
        assert result["model_version"] == "markov_learning_update_v2"

    snapshot = runtime_model_mapping_snapshot("TRANSITION_COUNTS")
    context = markov_global_context_key()
    sequence_key = markov_stage_transition_key(
        context_key=context, previous_stage="asset", behavior_flow=tuple(flow),
    )
    pair_key = markov_event_transition_key(
        context_key=context, previous_stage="asset", source_event="download",
    )
    assert snapshot[sequence_key]["runtime"] == 3
    assert snapshot[pair_key]["exec"] == 3
    assert markov.markov_transition_score("asset", flow, "runtime") == pytest.approx(0.125)
    assert 0.0 < markov.markov_transition_score("asset", flow, "archive") < 1.0


def test_stage948_markov_features_are_cold_start_neutral_without_chain_pattern_ownership():
    _reset_markov_state()
    cold = markov.compute_markov_features("asset", ["decode", "exec"], "runtime")
    assert cold["ready"] is False
    assert cold["transition"] == 0.0
    assert cold["rarity"] == 0.0
    assert cold["pair_anomaly"] == 0.0
    assert "known_suspicious_sequence" not in cold
    assert cold["sequence_anomaly"] == 0.0


def test_stage948_temporal_update_records_deduped_canonical_events_and_order_only_snapshot():
    node = "stage948-temporal-node-a"
    result = temporal.update_temporal(
        node, "asset", ["", "download", "download", "exec"],
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage948-temporal-a",
        ),
    )
    timeline = temporal.build_temporal_history_timeline(node)
    snapshot = temporal.snapshot_temporal(node)

    assert result["updated"] is True
    assert result["flow"] == ("download", "exec")
    assert [event["behavior_id"] for event in timeline] == ["download", "exec"]
    assert all(event["stage"] == "asset" for event in timeline)
    assert all(event["timestamp_kind"] == "ordinal_only" for event in timeline)
    assert snapshot["ready"] is True
    assert snapshot["observed_time_evidence"]["ready"] is False
    assert snapshot["unavailable_reason"] == "temporal_order_only_history"


def test_stage948_temporal_sequence_and_drift_use_recorded_ordered_history():
    node = "stage948-temporal-node-b"
    temporal.update_temporal(
        node, "asset", ["certutil_exec"],
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage948-temporal-b1",
        ),
    )
    temporal.update_temporal(
        node, "runtime", ["network_download"], previous_stage="asset",
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage948-temporal-b2",
        ),
    )

    score, hits = temporal.detect_sequence_patterns(node)
    drift = temporal.explain_temporal_drift(node)
    history = temporal_history_snapshot(node)

    assert len(history) == 2
    assert score == 0.0
    assert "execution.certutil_download" in hits
    assert "asset -> runtime" in drift


def test_stage948_temporal_validation_projects_external_chain_identity_without_chain_scoring():
    result = temporal.compute_temporal_validation(
        "stage948-temporal-node-c",
        tags=physical_tag_evidence(("certutil_exec", "network_download"), source_detector="stage948"),
        prev_stage="asset", curr_stage="runtime",
        markov={
            "transition": 0.0, "rarity": 0.0,
            "pair_anomaly": 0.0, "sequence_anomaly": 0.0,
        },
    )

    assert "execution.certutil_download" in result["chain_identities"]
    assert result["chain_score_contribution"] == 0.0
    assert [event["behavior_id"] for event in result["events"]] == [
        "certutil_exec", "network_download",
    ]
    assert result["score"] >= 0.0


def test_stage948_transition_probability_overlay_is_bounded_and_v5_schema_versioned():
    _reset_markov_state()
    for index in range(3):
        markov.update_markov_model(
            "asset", ["download", "exec", "network"], "runtime",
            learning_decision=accepted_learning_decision(
                target_names=("markov",), observation_id=f"stage948-overlay-{index}",
            ),
        )
    overlay = temporal.transition_probability_overlay(
        prev_stage="asset", tags=["download", "exec", "network"],
        curr_stage="runtime",
    )

    assert overlay["ready"] is True
    assert overlay["evidence_type"] == "sequence_probability"
    assert overlay["schema_version"] == "5.0"
    assert overlay["flow"] == ("download", "exec", "network")
    assert len(overlay["pair_probabilities"]) == 2
    assert 0.0 <= overlay["markov_anomaly"] <= 1.0
    assert 0.0 <= overlay["hidden_state"]["maturity"] <= 1.0
    assert overlay["observed_time_evidence"]["ready"] is False
