"""Stage 1472: graph runtime numeric boundaries must not crash on hostile scalar values."""

from __future__ import annotations

from Virus_Scan.models.graph.state import add_graph_edge, get_graph_node
from Virus_Scan.runtime.graph_state import reset_graph_state, update_graph_node_owned


class _HostileFloat:
    def __float__(self):  # pragma: no cover - exercised by graph runtime boundary
        raise RuntimeError("hostile graph numeric conversion")


def test_stage1472_graph_edge_hostile_weight_records_unavailable_reason() -> None:
    reset_graph_state()

    add_graph_edge("src", "dst", weight=_HostileFloat())
    node = get_graph_node("src")

    assert node is not None
    assert node["weights"]["dst"] == 1.0
    assert node["weight_unavailable_reasons"]["dst"] == "non_finite_graph_weight"


def test_stage1472_graph_node_hostile_risk_and_attention_are_sanitized() -> None:
    reset_graph_state()

    update_graph_node_owned("node", risk=_HostileFloat(), attention=_HostileFloat())
    node = get_graph_node("node")

    assert node is not None
    assert node["risk"] == 0.0
    assert node["attention"] == 0.0
    assert node["risk_unavailable_reason"] == "non_finite_graph_risk"
    assert node["attention_unavailable_reason"] == "non_finite_graph_attention"
