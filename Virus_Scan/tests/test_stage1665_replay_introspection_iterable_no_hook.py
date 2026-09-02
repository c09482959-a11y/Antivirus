from Virus_Scan.models.replay_introspection import (
    ReplayNode,
    compress_replay_nodes,
    garbage_collect_replay,
    replay_influence_graph,
    validate_replay_lineage,
)


class HostileReplayTags:
    touched = 0

    def __bool__(self):
        HostileReplayTags.touched += 1
        raise RuntimeError("do not call bool")

    def __iter__(self):
        HostileReplayTags.touched += 1
        raise RuntimeError("do not iterate tags")


class HostileReplayNodeSource:
    touched = 0

    def __bool__(self):
        HostileReplayNodeSource.touched += 1
        raise RuntimeError("do not call bool")

    def __iter__(self):
        HostileReplayNodeSource.touched += 1
        raise RuntimeError("do not iterate nodes")


def test_stage1665_replay_node_rejects_unknown_tags_without_iterating() -> None:
    HostileReplayTags.touched = 0

    node = ReplayNode("child", "root", HostileReplayTags(), 0.5, "origin", "reason")

    assert HostileReplayTags.touched == 0
    assert node.tags == ("<unavailable_replay_tags>",)


def test_stage1665_replay_node_source_rejected_without_iterating() -> None:
    HostileReplayNodeSource.touched = 0

    graph = replay_influence_graph(HostileReplayNodeSource())
    validation = validate_replay_lineage(HostileReplayNodeSource())
    compressed = compress_replay_nodes(HostileReplayNodeSource())
    kept = garbage_collect_replay(HostileReplayNodeSource())

    assert HostileReplayNodeSource.touched == 0
    assert graph["nodes"] == 1
    assert graph["attribution"]["<unavailable_replay_node>"]["rationale"] == "unsupported_replay_node_source"
    assert validation["nodes"] == 1
    assert compressed[0].rationale == "unsupported_replay_node_source"
    assert kept[0].rationale == "unsupported_replay_node_source"


def test_stage1665_builtin_replay_sequences_still_materialize() -> None:
    nodes = [
        ReplayNode("root", tags=["loader"], influence=0.1),
        ReplayNode("child", "root", ("network",), 0.8, "scanner", "reason"),
    ]

    graph = replay_influence_graph(nodes)

    assert graph["nodes"] == 2
    assert graph["depth"] == 2
    assert graph["attribution"]["root"]["tags"] == ["loader"]
    assert graph["attribution"]["child"]["tags"] == ["network"]
