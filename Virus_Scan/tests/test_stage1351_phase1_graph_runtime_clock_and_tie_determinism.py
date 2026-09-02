from __future__ import annotations

import inspect

from Virus_Scan.runtime import graph_state
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_node_snapshot,
    graph_node_snapshots,
    graph_snapshot,
    prune_graph_owned,
    reset_graph_state,
    update_graph_node_owned,
)


def _seed_graph_sequence() -> dict[str, object]:
    reset_graph_state()
    update_graph_node_owned("node:root", risk=2.0, tags={"execution"})
    add_graph_edge_owned("node:root", "tag:execution", edge_type="tag", weight=3.0)
    add_graph_edge_owned("node:root", "tag:persistence", edge_type="tag", weight=1.0)
    return {
        "root": dict(graph_node_snapshot("node:root") or {}),
        "tag_execution": dict(graph_node_snapshot("tag:execution") or {}),
        "tag_persistence": dict(graph_node_snapshot("tag:persistence") or {}),
    }


def test_stage1351_runtime_graph_mutation_uses_deterministic_logical_timestamps() -> None:
    first = _seed_graph_sequence()
    second = _seed_graph_sequence()

    assert first["root"]["last_seen"] == second["root"]["last_seen"] == 3.0
    assert first["root"]["edge_time"] == second["root"]["edge_time"]
    assert first["tag_execution"]["last_seen"] == second["tag_execution"]["last_seen"] == 2.0
    assert first["tag_persistence"]["last_seen"] == second["tag_persistence"]["last_seen"] == 3.0


def test_stage1351_runtime_graph_state_has_no_wall_clock_import_or_call() -> None:
    source = inspect.getsource(graph_state)

    assert "from time import time" not in source
    assert "time()" not in source


def test_stage1351_graph_node_snapshot_iteration_is_sorted_by_canonical_key() -> None:
    reset_graph_state()
    update_graph_node_owned("node:z", risk=1.0)
    update_graph_node_owned("node:a", risk=1.0)
    update_graph_node_owned("node:m", risk=1.0)

    assert [node for node, _snapshot in graph_node_snapshots()] == ["node:a", "node:m", "node:z"]


def test_stage1351_graph_node_prune_ties_use_canonical_node_key() -> None:
    reset_graph_state()
    update_graph_node_owned("node:c", risk=1.0, last_seen=10.0)
    update_graph_node_owned("node:a", risk=1.0, last_seen=10.0)
    update_graph_node_owned("node:b", risk=1.0, last_seen=10.0)

    prune_graph_owned(max_nodes=2, max_edges_per_node=10)

    assert list(graph_snapshot().keys()) == ["node:b", "node:c"]


def test_stage1351_graph_edge_prune_ties_use_canonical_edge_key() -> None:
    reset_graph_state()
    add_graph_edge_owned("node:root", "tag:z", edge_type="tag", weight=1.0)
    add_graph_edge_owned("node:root", "tag:a", edge_type="tag", weight=1.0)
    add_graph_edge_owned("node:root", "tag:m", edge_type="tag", weight=1.0)

    prune_graph_owned(max_nodes=10, max_edges_per_node=2)

    snapshot = graph_node_snapshot("node:root")
    assert snapshot is not None
    assert snapshot["edges"] == frozenset({"tag:a", "tag:m"})
    assert "tag:z" not in snapshot["weights"]
