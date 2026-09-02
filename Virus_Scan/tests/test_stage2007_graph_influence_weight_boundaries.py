"""Stage 2007 graph influence no-hook weight boundary regressions."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.graph.influence import _ranked_attention_weight_items
from Virus_Scan.models.graph import links as graph_links
from Virus_Scan.models.graph.links import incremental_graph_update, link_tags_to_graph, link_temporal_to_graph


class HostileWeight:
    __slots__ = ("calls",)

    def __init__(self, calls: list[str]) -> None:
        object.__setattr__(self, "calls", calls)

    def __getattribute__(self, name: str):
        if name == "calls":
            return object.__getattribute__(self, name)
        object.__getattribute__(self, "calls").append("__getattribute__")
        raise AssertionError("caller-owned weight attribute hook executed")

    def __float__(self) -> float:
        self.calls.append("__float__")
        raise AssertionError("caller-owned float hook executed")

    def __int__(self) -> int:
        self.calls.append("__int__")
        raise AssertionError("caller-owned int hook executed")

    def __bool__(self) -> bool:
        self.calls.append("__bool__")
        raise AssertionError("caller-owned bool hook executed")

    def __lt__(self, other: object) -> bool:
        self.calls.append("__lt__")
        raise AssertionError("caller-owned compare hook executed")

    def __repr__(self) -> str:
        self.calls.append("__repr__")
        raise AssertionError("caller-owned repr hook executed")


def test_graph_influence_ranking_rejects_hostile_weights_before_sort_comparison_hooks():
    calls: list[str] = []
    ranked = _ranked_attention_weight_items({"low": 0.1, "bad": HostileWeight(calls), "high": 0.9})

    assert ranked == (("high", 0.9), ("low", 0.1))
    assert calls == []




def test_graph_link_boundaries_reject_hostile_nodes_and_tag_sequences_without_hooks():
    node_calls: list[str] = []
    tag_calls: list[str] = []
    yara_calls: list[str] = []

    hostile_node = HostileWeight(node_calls)
    hostile_tags = HostileWeight(tag_calls)

    incremental_graph_update(hostile_node, tag_evidence=hostile_tags)  # type: ignore[arg-type]
    link_tags_to_graph(hostile_node, hostile_tags)  # type: ignore[arg-type]
    result = link_temporal_to_graph(hostile_node, "start", hostile_tags, "end")  # type: ignore[arg-type]

    assert type(result["linked"]) is bool
    assert node_calls == []
    assert tag_calls == []
    assert yara_calls == []
    assert not hasattr(graph_links, "link_yara_to_graph")


def test_graph_influence_repaired_source_snippets_absent():
    forbidden_by_path = {
        "Virus_Scan/models/graph/features.py": [
            "log_error(f'graph feature error: {e}')",
        ],
        "Virus_Scan/models/graph/influence.py": [
            "ranked = sorted(weights.items(), key=lambda x: x[1], reverse=True)",
            "ranked = sorted(items, key=lambda x: x[1], reverse=True)",
            "log_error(f'graph attention propagation failed with canonical graph scoring authority: {e}')",
            "log_error(f'reinforce_cluster_with_graph failed: {e}')",
            "log_error(f'reinforce_graph_with_cluster failed: {e}')",
        ],
        "Virus_Scan/models/graph/links.py": [
            "node_text = safe_graph_text(node)",
            "add_graph_edge(node, f'stage:{stage}', edge_type='stage', weight=1.2)",
            "for phase, matched in phase_hits.items():",
            "record_graph_input_degraded('graph_temporal_link_input_degraded', tags_reason, node=safe_graph_text(node))",
            "add_graph_edge(temporal_state_node_key(node), f\"transition:{prev_stage}->{curr_stage}:{'->'.join(flow[:6])}\", edge_type='temporal', weight=weight)",
            "record_graph_input_degraded('graph_yara_link_input_degraded', yara_reason, node=safe_graph_text(node))",
            "add_graph_edge(node, f'yara:{y}', 'yara', 2.0)",
        ],
    }
    for path, snippets in forbidden_by_path.items():
        source = Path(path).read_text(encoding="utf-8")
        for snippet in snippets:
            assert snippet not in source
