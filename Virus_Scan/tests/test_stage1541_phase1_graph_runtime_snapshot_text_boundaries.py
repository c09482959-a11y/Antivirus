from __future__ import annotations

from Virus_Scan.runtime.graph_state import (
    GRAPH_RUNTIME_TEXT_UNAVAILABLE,
    add_graph_edge_owned,
    graph_node_snapshot,
    graph_node_snapshots,
    graph_snapshot,
    graph_vector_node_key,
    reset_graph_state,
    update_graph_node_owned,
)


class HostileText:
    calls = 0

    def __str__(self) -> str:  # pragma: no cover - must never be called
        type(self).calls += 1
        raise AssertionError("caller-owned __str__ executed")


class HostileTextTwin(HostileText):
    pass


def test_stage1541_graph_vector_node_key_does_not_call_hostile_object_str() -> None:
    HostileText.calls = 0
    node = HostileText()

    text = graph_vector_node_key(node)

    assert text == f"{GRAPH_RUNTIME_TEXT_UNAVAILABLE}:HostileText"
    assert HostileText.calls == 0


def test_stage1541_graph_node_snapshot_detaches_hostile_edges_tags_and_metadata() -> None:
    reset_graph_state()
    HostileText.calls = 0
    hostile_edge = HostileText()
    hostile_tag = HostileText()
    hostile_key = HostileText()
    hostile_value = HostileText()

    update_graph_node_owned("node:hostile", tags=(hostile_tag,), metadata={hostile_key: hostile_value})
    add_graph_edge_owned("node:hostile", hostile_edge, edge_type="tag", weight=float("nan"))

    snapshot = graph_node_snapshot("node:hostile")

    unavailable = f"{GRAPH_RUNTIME_TEXT_UNAVAILABLE}:HostileText"
    assert snapshot is not None
    assert unavailable in snapshot["tags"]
    assert unavailable in snapshot["edges"]
    assert snapshot["weights"][unavailable] == 1.0
    assert snapshot["weight_unavailable_reasons"][unavailable] == "non_finite_graph_weight"

    full_snapshot = graph_snapshot()["node:hostile"]
    assert full_snapshot["metadata"][unavailable] == unavailable
    assert HostileText.calls == 0


def test_stage1541_graph_full_snapshot_preserves_duplicate_unavailable_keys_deterministically() -> None:
    reset_graph_state()
    first = HostileTextTwin()
    second = HostileTextTwin()

    update_graph_node_owned(first, metadata={"value": "first"})
    update_graph_node_owned(second, metadata={"value": "second"})

    snapshot = graph_snapshot()
    rows = graph_node_snapshots()

    base = f"{GRAPH_RUNTIME_TEXT_UNAVAILABLE}:HostileTextTwin"
    assert tuple(snapshot.keys()) == (base, f"{base}#2")
    assert tuple(node for node, _data in rows) == (base, f"{base}#2")
    assert snapshot[base]["metadata"]["value"] == "first"
    assert snapshot[f"{base}#2"]["metadata"]["value"] == "second"
