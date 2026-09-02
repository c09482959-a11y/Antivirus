"""Stage 1421: replay introspection must freeze hostile inputs without truthiness crashes."""

from Virus_Scan.models.replay_introspection import (
    ReplayNode,
    compress_replay_nodes,
    garbage_collect_replay,
    replay_influence_graph,
)


class _HostileBoolFloat:
    def __bool__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("hostile bool conversion")

    def __float__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("hostile float conversion")


class _HostileTags:
    touched = 0

    def __bool__(self):  # pragma: no cover - boundary must not call
        _HostileTags.touched += 1
        raise RuntimeError("hostile bool conversion")

    def __iter__(self):  # pragma: no cover - boundary must not call
        _HostileTags.touched += 1
        raise RuntimeError("hostile tag iteration")


class _HostileNodes:
    touched = 0

    def __bool__(self):  # pragma: no cover - boundary must not call
        _HostileNodes.touched += 1
        raise RuntimeError("hostile bool conversion")

    def __iter__(self):  # pragma: no cover - boundary must not call
        _HostileNodes.touched += 1
        raise RuntimeError("hostile node iteration")


def test_stage1421_replay_node_hostile_tags_and_influence_are_explicitly_sanitized():
    _HostileTags.touched = 0
    node = ReplayNode("child", "root", _HostileTags(), _HostileBoolFloat(), "origin", "reason")

    assert _HostileTags.touched == 0
    assert node.tags == ("<unavailable_replay_tags>",)
    assert node.influence == 0.0
    assert node.parent_id == "root"


def test_stage1421_replay_graph_hostile_node_container_emits_unavailable_evidence_not_clean_empty():
    _HostileNodes.touched = 0
    graph = replay_influence_graph(_HostileNodes())

    assert _HostileNodes.touched == 0
    assert graph["nodes"] == 1
    assert graph["depth"] == 1
    assert "<unavailable_replay_node>" in graph["attribution"]
    unavailable = graph["attribution"]["<unavailable_replay_node>"]
    assert unavailable["origin"] == "replay_introspection"
    assert unavailable["rationale"] == "unsupported_replay_node_source"
    assert unavailable["tags"] == ["replay_nodes_unavailable", "unsupported_replay_node_source"]


def test_stage1421_replay_compression_does_not_truthiness_probe_node_fields():
    nodes = (
        ReplayNode("child", "root", _HostileTags(), _HostileBoolFloat(), "", "first"),
        ReplayNode("child", "root", ("network",), 0.8, "scanner", "second"),
    )

    compressed = compress_replay_nodes(nodes)
    kept = garbage_collect_replay(nodes)

    assert len(compressed) == 1
    assert compressed[0].tags == ("<unavailable_replay_tags>", "network")
    assert compressed[0].influence == 0.8
    assert kept[0].node_id == "child"
