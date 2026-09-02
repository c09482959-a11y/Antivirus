from types import MappingProxyType

import pytest

from Virus_Scan.models.graph import (
    compute_attention_weights,
    enforce_graph_decay,
    integrate_graph_intelligence,
    propagate_graph_attention,
    propagate_graph_attention_refined,
    safe_attention_lookup,
)
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_node_snapshot,
    graph_snapshot,
    reset_graph_state,
    update_graph_node_owned,
)


def test_stage1153_graph_attention_helpers_are_callable_and_bounded():
    reset_graph_state()
    add_graph_edge_owned("node:graph", "tag:execution", edge_type="tag", weight=1.0)
    add_graph_edge_owned("node:graph", "yara:hit", edge_type="yara", weight=2.0)

    weights = compute_attention_weights("node:graph")

    assert set(weights) == {"tag:execution", "yara:hit"}
    assert all(0.0 <= value <= 1.0 for value in weights.values())
    assert 0.99 <= sum(weights.values()) <= 1.01
    frozen_weights = MappingProxyType(dict(weights))
    assert safe_attention_lookup(frozen_weights, "tag:execution") == weights["tag:execution"]
    assert safe_attention_lookup(frozen_weights, "missing") == 0.0
    assert 0.0 <= propagate_graph_attention("node:graph") <= 1.0
    assert 0.0 <= propagate_graph_attention_refined("node:graph") <= 1.0


def test_stage1153_integrate_graph_intelligence_does_not_crash_and_updates_attention():
    reset_graph_state()
    add_graph_edge_owned("node:intel", "tag:persistence", edge_type="tag", weight=1.0)

    before = graph_node_snapshot("node:intel")
    assert before["attention"] == 0.0

    integrate_graph_intelligence("node:intel", tags=("persistence",))
    after = graph_node_snapshot("node:intel")

    assert 0.0 <= after["attention"] <= 1.0
    assert after["attention"] > 0.0
    assert after["weights"]["tag:persistence"] <= before["weights"]["tag:persistence"]


def test_stage1153_graph_runtime_metadata_updates_replace_stale_values():
    reset_graph_state()
    update_graph_node_owned("node:metadata", attention=0.1, metadata={"values": ["old"]})
    update_graph_node_owned("node:metadata", attention=0.7, metadata={"values": ["new"]})

    snapshot = graph_snapshot()["node:metadata"]

    assert snapshot["attention"] == pytest.approx(0.7)
    assert snapshot["metadata"]["values"] == ("new",)


def test_stage1153_graph_decay_is_runtime_owner_controlled_and_deterministic():
    reset_graph_state()
    add_graph_edge_owned("node:decay", "tag:network", edge_type="tag", weight=2.0)

    enforce_graph_decay(decay=0.5, min_weight=0.25)
    once = graph_node_snapshot("node:decay")["weights"]["tag:network"]
    enforce_graph_decay(decay=0.5, min_weight=0.25)
    twice = graph_node_snapshot("node:decay")["weights"]["tag:network"]

    assert once == pytest.approx(1.0)
    assert twice == pytest.approx(0.5)
