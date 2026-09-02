from Virus_Scan.models.replay_introspection import (
    compress_replay_nodes,
    garbage_collect_replay,
    replay_influence_graph,
    validate_replay_lineage,
    why_suspicious_report,
)


class _BrokenReplayNodeSource:
    touched = 0

    def __iter__(self):
        _BrokenReplayNodeSource.touched += 1
        raise RuntimeError("iterator unavailable")


def test_stage1469_replay_graph_records_node_iteration_failure_as_evidence():
    _BrokenReplayNodeSource.touched = 0
    graph = replay_influence_graph(_BrokenReplayNodeSource())

    assert _BrokenReplayNodeSource.touched == 0
    assert graph["nodes"] == 1
    assert graph["depth"] == 1
    record = graph["attribution"]["<unavailable_replay_node>"]
    assert record["origin"] == "replay_introspection"
    assert record["rationale"] == "unsupported_replay_node_source"
    assert record["tags"] == ["replay_nodes_unavailable", "unsupported_replay_node_source"]


def test_stage1469_replay_lineage_validation_does_not_report_failed_source_as_clean_empty():
    _BrokenReplayNodeSource.touched = 0
    result = validate_replay_lineage(_BrokenReplayNodeSource())

    assert _BrokenReplayNodeSource.touched == 0
    assert result["nodes"] == 1
    assert result["depth"] == 1
    assert result["ok"] is True
    assert "<unavailable_replay_node>" in result["graph"]["attribution"]


def test_stage1469_replay_compression_and_reports_preserve_unavailable_evidence():
    _BrokenReplayNodeSource.touched = 0
    compressed = compress_replay_nodes(_BrokenReplayNodeSource())
    kept = garbage_collect_replay(_BrokenReplayNodeSource())
    report = why_suspicious_report(_BrokenReplayNodeSource())

    assert _BrokenReplayNodeSource.touched == 0
    assert [node.node_id for node in compressed] == ["<unavailable_replay_node>"]
    assert [node.node_id for node in kept] == ["<unavailable_replay_node>"]
    assert report["graph_summary"] == {"nodes": 1, "depth": 1}
    assert report["top_influences"][0][0] == "<unavailable_replay_node>"
