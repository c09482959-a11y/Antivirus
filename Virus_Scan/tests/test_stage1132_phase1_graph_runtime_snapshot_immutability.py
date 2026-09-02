from collections.abc import Mapping

import pytest

from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_node_snapshot,
    graph_node_snapshots,
    reset_graph_state,
    update_graph_node_owned,
)
from Virus_Scan.models.graph import score_attack_chain_presence


def test_stage1132_graph_node_snapshot_is_detached_and_immutable():
    reset_graph_state()
    update_graph_node_owned("file:a", risk=7.0, tags=("execution",))
    add_graph_edge_owned("file:a", "tag:execution", edge_type="tag", weight=2.0)

    snapshot = graph_node_snapshot("file:a")

    assert isinstance(snapshot, Mapping)
    assert snapshot["edges"] == frozenset({"tag:execution"})
    assert snapshot["tags"] == frozenset({"execution"})
    with pytest.raises(TypeError):
        snapshot["risk"] = 99.0
    with pytest.raises(AttributeError):
        snapshot["edges"].add("tag:persistence")
    with pytest.raises(TypeError):
        snapshot["weights"]["tag:execution"] = 9.0

    add_graph_edge_owned("file:a", "tag:persistence", edge_type="tag", weight=1.0)
    assert snapshot["edges"] == frozenset({"tag:execution"})
    assert graph_node_snapshot("file:a")["edges"] == frozenset({"tag:execution", "tag:persistence"})


def test_stage1132_graph_snapshot_iteration_is_immutable_and_model_readable():
    reset_graph_state()
    update_graph_node_owned("node:1", tags=("execution", "persistence"))
    add_graph_edge_owned("node:1", "tag:execution", edge_type="tag", weight=1.0)

    snapshots = graph_node_snapshots()

    assert isinstance(snapshots, tuple)
    with pytest.raises(AttributeError):
        snapshots.append(("node:2", {}))
    assert snapshots[0][1]["tags"] == frozenset({"execution", "persistence"})
    assert score_attack_chain_presence("node:1") >= 0.0
