"""Stage 1666: replay introspection rejects PathLike hooks without executing __fspath__."""

from Virus_Scan.models.replay_introspection import ReplayNode, replay_influence_graph, why_suspicious_report


class HostileReplayPathLike:
    touched = 0

    def __fspath__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("caller-owned __fspath__ must not execute")

    def __str__(self):  # pragma: no cover - failure proves raw str execution
        type(self).touched += 1
        raise RuntimeError("caller-owned __str__ must not execute")

    def __repr__(self):  # pragma: no cover - failure proves raw repr execution
        type(self).touched += 1
        raise RuntimeError("caller-owned __repr__ must not execute")


def test_stage1666_replay_node_rejects_pathlike_identity_without_fspath() -> None:
    HostileReplayPathLike.touched = 0
    hostile = HostileReplayPathLike()

    node = ReplayNode(hostile, hostile, (hostile,), 0.25, hostile, hostile)

    assert HostileReplayPathLike.touched == 0
    assert node.node_id == "<unavailable_replay_node>"
    assert node.parent_id == "<unavailable_replay_parent>"
    assert node.tags == ("<unavailable_replay_tag>",)
    assert node.origin == ""
    assert node.rationale == ""


def test_stage1666_replay_report_rejects_pathlike_requested_node_without_fspath() -> None:
    HostileReplayPathLike.touched = 0
    hostile = HostileReplayPathLike()
    nodes = [ReplayNode("root"), ReplayNode("child", "root")]

    graph = replay_influence_graph(nodes)
    report = why_suspicious_report(nodes, node_id=hostile)

    assert HostileReplayPathLike.touched == 0
    assert graph["nodes"] == 2
    assert report["graph_summary"] == {"nodes": 2, "depth": 2}
    assert "top_influences" in report


def test_stage1666_exact_primitive_replay_text_still_materializes() -> None:
    node = ReplayNode("child", "root", ("tag",), 1.0, "origin", "reason")

    assert node.node_id == "child"
    assert node.parent_id == "root"
    assert node.tags == ("tag",)
    assert node.origin == "origin"
    assert node.rationale == "reason"
