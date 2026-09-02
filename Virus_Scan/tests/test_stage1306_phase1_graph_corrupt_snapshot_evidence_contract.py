from __future__ import annotations

from Virus_Scan.models import graph
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    reset_graph_state,
    update_graph_node_owned,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage1306_graph_attention_handles_corrupt_snapshot_times_without_crash() -> None:
    reset_graph_state()
    add_graph_edge_owned("node:corrupt-time", "node:child", edge_type="temporal", weight=1.0)
    update_graph_node_owned(
        "node:corrupt-time",
        last_seen="not-a-time",
        edge_time={"node:child": "also-not-a-time"},
    )

    score = graph.propagate_graph_attention("node:corrupt-time")

    assert 0.0 <= score <= 1.0


def test_stage1306_graph_relationship_reports_corrupt_time_evidence_as_unavailable() -> None:
    reset_graph_state()
    add_graph_edge_owned("node:corrupt-time", "tag:execution", edge_type="tag", weight=1.0)
    update_graph_node_owned(
        "node:corrupt-time",
        last_seen="not-a-time",
        edge_time={"tag:execution": "also-not-a-time"},
    )

    layer = graph.compute_graph_relationship_layer("node:corrupt-time", tags=physical_tag_evidence(("execution",)))

    assert layer["graph_relationship_ready"] is False
    assert layer["graph_unavailable_reason"] == "corrupt_graph_time_evidence"
    assert layer["graph_features"]["graph_features_ready"] is False
    assert layer["graph_features"]["graph_unavailable_reason"] == "corrupt_graph_time_evidence"
