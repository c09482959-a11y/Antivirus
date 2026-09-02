from dataclasses import FrozenInstanceError
from types import MappingProxyType

import pytest

from Virus_Scan.contracts.temporal_event import TemporalEvent
from Virus_Scan.models import temporal
from Virus_Scan.runtime.temporal_state import (
    temporal_has_node,
    temporal_history_snapshot,
    temporal_node_state_snapshot,
)
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


def _decision(name: str):
    return accepted_learning_decision(
        target_names=("temporal",), observation_id=name,
    )


def test_stage1129_temporal_history_snapshot_is_immutable_and_detached():
    node = "stage1129-temporal-history-node"
    temporal.update_temporal(
        node, "asset", ["download", "exec"],
        learning_decision=_decision("stage1129-history-1"),
    )

    history = temporal_history_snapshot(node)

    assert isinstance(history, tuple)
    assert all(type(event) is TemporalEvent for event in history)
    assert tuple(event.behavior_id for event in history) == ("download", "exec")
    assert tuple(event.stage for event in history) == ("asset", "asset")
    assert all(event.timestamp_kind == "ordinal_only" for event in history)
    assert all(event.timestamp_value is None for event in history)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        history[-1].stage = "mutated"

    temporal.update_temporal(
        node, "runtime", ["network", "persistence"], previous_stage="asset",
        learning_decision=_decision("stage1129-history-2"),
    )
    assert len(history) == 2
    assert len(temporal_history_snapshot(node)) == 4


def test_stage1129_temporal_state_snapshot_is_immutable_and_does_not_create_missing_nodes():
    missing_node = "stage1129-temporal-missing-node"
    assert temporal_has_node(missing_node) is False

    missing_snapshot = temporal_node_state_snapshot(missing_node)

    assert isinstance(missing_snapshot, MappingProxyType)
    assert missing_snapshot["history"] == ()
    assert isinstance(missing_snapshot["hidden_state"], MappingProxyType)
    assert temporal_has_node(missing_node) is False
    with pytest.raises(TypeError):
        missing_snapshot["belief"] = 1.0


def test_stage1129_temporal_state_snapshot_freezes_canonical_v5_hidden_state():
    node = "stage1129-temporal-state-node"
    temporal.update_temporal(
        node, "asset", ["download", "exec"],
        learning_decision=_decision("stage1129-state-1"),
    )
    temporal.update_temporal(
        node, "runtime", ["network", "persistence"], previous_stage="asset",
        learning_decision=_decision("stage1129-state-2"),
    )
    result = temporal.snapshot_temporal(node)
    assert result["ready"] is True

    snapshot = temporal_node_state_snapshot(node)

    assert isinstance(snapshot, MappingProxyType)
    assert isinstance(snapshot["history"], tuple)
    assert isinstance(snapshot["hidden_state"], MappingProxyType)
    assert snapshot["hidden_state"]["schema_version"] == "temporal_accumulator_state_v5"
    assert snapshot["hidden_state"]["model_version"] == "temporal_evidence_accumulator_v5"
    with pytest.raises(TypeError):
        snapshot["hidden_state"]["posterior_belief"] = 1.0
