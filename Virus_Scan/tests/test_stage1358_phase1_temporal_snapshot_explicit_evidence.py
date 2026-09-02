from __future__ import annotations

from Virus_Scan.contracts.temporal_accumulator import TEMPORAL_ACCUMULATOR_VERSION
from Virus_Scan.models import temporal
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


def test_stage1358_snapshot_temporal_cold_start_has_explicit_unavailable_evidence():
    result = temporal.snapshot_temporal("stage1358-cold-start-node")

    assert result["ready"] is False
    assert result["belief"] == 0.0
    assert result["evidence_type"] == "temporal_snapshot"
    assert result["reason"] == "insufficient_temporal_history"
    assert result["unavailable_reason"] == "insufficient_temporal_history"
    assert result["temporal_model_version"] == TEMPORAL_ACCUMULATOR_VERSION
    assert result["ordered_sequence_evidence"]["event_count"] == 0
    assert result["observed_time_evidence"]["ready"] is False
    assert result["hidden_state"]["schema_version"] == "temporal_accumulator_state_v5"


def test_stage1358_snapshot_temporal_ready_evidence_separates_order_from_elapsed_time():
    node = "stage1358-ready-node"
    temporal.update_temporal(
        node, "asset", ["download", "exec"],
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage1358-ready-1",
        ),
    )
    temporal.update_temporal(
        node, "runtime", ["network", "persistence"], previous_stage="asset",
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage1358-ready-2",
        ),
    )

    result = temporal.snapshot_temporal(node)

    assert result["ready"] is True
    assert result["evidence_type"] == "temporal_snapshot"
    assert result["temporal_model_version"] == TEMPORAL_ACCUMULATOR_VERSION
    assert result["ordered_sequence_evidence"]["ready"] is True
    assert result["ordered_sequence_evidence"]["event_count"] == 4
    assert result["observed_time_evidence"]["ready"] is False
    assert result["unavailable_reason"] == "temporal_order_only_history"
    assert isinstance(result["markov_transition_evidence"]["pairs"], tuple)


def test_stage1358_update_temporal_no_flow_returns_immutable_empty_flow():
    result = temporal.update_temporal(
        "stage1358-no-flow-node", "asset", ["", None],
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage1358-no-flow",
        ),
    )

    assert result["updated"] is False
    assert result["reason"] == "no_behavior_flow"
    assert result["flow"] == ()
