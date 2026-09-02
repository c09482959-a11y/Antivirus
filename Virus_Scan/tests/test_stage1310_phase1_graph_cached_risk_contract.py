from __future__ import annotations

import math

from Virus_Scan.models import graph
from Virus_Scan.models.graph.cache import GRAPH_RISK_CACHE
from Virus_Scan.models.api import adaptive_signals


def _cache_key(node: str) -> str:
    return graph.cache_key("graph_risk_enhanced", node)


def test_stage1310_graph_risk_cache_does_not_leak_nonfinite_model_value() -> None:
    node = "stage1310_nonfinite_cached_graph_risk_node"
    key = _cache_key(node)
    GRAPH_RISK_CACHE[key] = math.inf

    risk = graph.get_graph_risk_enhanced(node)

    assert risk == 0.0
    assert key not in GRAPH_RISK_CACHE


def test_stage1310_graph_risk_cache_does_not_leak_out_of_bounds_model_value() -> None:
    node = "stage1310_out_of_bounds_cached_graph_risk_node"
    key = _cache_key(node)
    GRAPH_RISK_CACHE[key] = 4.2

    risk = graph.get_graph_risk_enhanced(node)

    assert risk == 0.0
    assert key not in GRAPH_RISK_CACHE


def test_stage1310_public_adaptive_graph_signal_reads_only_bounded_cached_risk() -> None:
    node = "stage1310_public_cached_graph_risk_node"
    key = _cache_key(node)
    GRAPH_RISK_CACHE[key] = 0.42

    risk = adaptive_signals.get_graph_risk_enhanced(node)

    assert risk == 0.42
    assert GRAPH_RISK_CACHE[key] == 0.42
