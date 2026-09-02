"""Stage 1471: malformed replay node sources must not materialize as clean empty graphs."""

from __future__ import annotations

from Virus_Scan.models.replay_introspection import (
    compress_replay_nodes,
    replay_influence_graph,
    validate_replay_lineage,
    why_suspicious_report,
)


def test_stage1471_non_iterable_replay_node_source_emits_unavailable_evidence() -> None:
    graph = replay_influence_graph(object())

    assert graph["nodes"] == 1
    record = graph["attribution"]["<unavailable_replay_node>"]
    assert record["origin"] == "replay_introspection"
    assert record["rationale"] == "unsupported_replay_node_source"
    assert record["tags"] == ["replay_nodes_unavailable", "unsupported_replay_node_source"]


def test_stage1471_text_replay_node_source_is_not_a_clean_empty_lineage() -> None:
    result = validate_replay_lineage("not-a-node-source")
    compressed = compress_replay_nodes("not-a-node-source")
    report = why_suspicious_report("not-a-node-source")

    assert result["nodes"] == 1
    assert "<unavailable_replay_node>" in result["graph"]["attribution"]
    assert [node.node_id for node in compressed] == ["<unavailable_replay_node>"]
    assert report["graph_summary"] == {"nodes": 1, "depth": 1}
