from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.graph.attention import propagate_graph_attention, safe_attention_lookup
from Virus_Scan.models.graph.cache import cache_key
from Virus_Scan.models.graph.risk import GRAPH_RISK_CACHE, get_graph_risk_enhanced_evidence
from Virus_Scan.runtime.graph_state import add_graph_edge_owned, reset_graph_state, update_graph_node_owned


class HostileNumber:
    touched = 0

    def __float__(self):  # pragma: no cover - failure proves caller-owned numeric hook ran
        type(self).touched += 1
        raise AssertionError("caller-owned float hook executed")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned int hook executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned bool hook executed")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned text hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook executed")


class HostileDepth(HostileNumber):
    pass


def test_stage1999_graph_attention_lookup_rejects_hostile_metric_without_numeric_hooks() -> None:
    HostileNumber.touched = 0

    score = safe_attention_lookup({"edge:target": HostileNumber()}, "edge:target")

    assert score == 0.0
    assert HostileNumber.touched == 0


def test_stage1999_graph_attention_depth_boundary_does_not_execute_hostile_hooks() -> None:
    HostileDepth.touched = 0
    reset_graph_state()
    add_graph_edge_owned("node:root", "node:child", edge_type="tag", weight=0.5)
    update_graph_node_owned("node:root", last_seen=10.0, edge_time={"node:child": 10.0})
    update_graph_node_owned("node:child", last_seen=10.0)

    score = propagate_graph_attention("node:root", depth=HostileDepth())

    assert 0.0 <= score <= 1.0
    assert HostileDepth.touched == 0


def test_stage1999_graph_risk_cache_rejects_hostile_metric_without_float_hook() -> None:
    HostileNumber.touched = 0
    reset_graph_state()
    GRAPH_RISK_CACHE.clear()
    add_graph_edge_owned("node:risk", "tag:execution", edge_type="tag", weight=1.0)
    GRAPH_RISK_CACHE[cache_key("graph_risk_enhanced", "node:risk")] = HostileNumber()

    evidence = get_graph_risk_enhanced_evidence("node:risk")

    assert evidence["ready"] is True
    assert 0.0 <= evidence["risk"] <= 1.0
    assert HostileNumber.touched == 0


def test_stage1999_graph_metric_sources_do_not_call_generic_safe_clamp() -> None:
    for source_path in (
        Path("Virus_Scan/models/graph/attention.py"),
        Path("Virus_Scan/models/graph/chains.py"),
        Path("Virus_Scan/models/graph/cluster_projection.py"),
        Path("Virus_Scan/models/graph/evidence.py"),
        Path("Virus_Scan/models/graph/risk.py"),
    ):
        source = source_path.read_text(encoding="utf-8")
        assert "safe_clamp" not in source
        assert "graph_unit_interval" in source
