"""Stage 1533: replay introspection must not coerce unsupported objects with raw str()."""
from __future__ import annotations

from Virus_Scan.models.replay_introspection import ReplayNode, replay_influence_graph, why_suspicious_report


class _HostileObject:
    def __init__(self, label: str = "hostile") -> None:
        self.label = label
        self.str_calls = 0
        self.bool_calls = 0

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError(f"raw __str__ used for {self.label}")

    def __bool__(self):  # pragma: no cover - failure proves truthiness probing regressed
        self.bool_calls += 1
        raise AssertionError(f"truthiness used for {self.label}")


class _HostilePath:
    def __init__(self) -> None:
        self.str_calls = 0
        self.fspath_calls = 0

    def __fspath__(self):  # pragma: no cover - failure proves caller-owned path hook execution
        self.fspath_calls += 1
        raise RuntimeError("path text unavailable")

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("raw path __str__ used")


def test_stage1533_replay_node_unsupported_objects_emit_unavailable_text_without_raw_str():
    node_id = _HostileObject("node")
    parent_id = _HostileObject("parent")
    tag = _HostileObject("tag")
    origin = _HostileObject("origin")
    rationale = _HostileObject("rationale")

    node = ReplayNode(node_id, parent_id, (tag,), 0.25, origin, rationale)

    assert node.node_id == "<unavailable_replay_node>"
    assert node.parent_id == "<unavailable_replay_parent>"
    assert node.tags == ("<unavailable_replay_tag>",)
    assert node.origin == ""
    assert node.rationale == ""
    assert node_id.str_calls == 0
    assert parent_id.str_calls == 0
    assert tag.str_calls == 0
    assert origin.str_calls == 0
    assert rationale.str_calls == 0


def test_stage1533_replay_report_requested_node_pathlike_failure_does_not_use_raw_str():
    path = _HostilePath()
    nodes = [ReplayNode("root"), ReplayNode("child", "root")]

    graph = replay_influence_graph(nodes)
    report = why_suspicious_report(nodes, node_id=path)

    assert graph["nodes"] == 2
    assert report["graph_summary"] == {"nodes": 2, "depth": 2}
    assert "top_influences" in report
    assert path.fspath_calls == 0
    assert path.str_calls == 0
