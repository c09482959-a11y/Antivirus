from __future__ import annotations

import ast
import time
from pathlib import Path

from Virus_Scan.models import graph
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_has_node,
    graph_snapshot,
    reset_graph_state,
)

GRAPH_MODEL = Path("Virus_Scan/models/graph/attention.py")


def _function_source(name: str) -> str:
    source = GRAPH_MODEL.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(GRAPH_MODEL))
    node = next(
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    return ast.get_source_segment(source, node) or ""


def test_stage1186_graph_attention_uses_snapshot_time_not_wall_clock_decay() -> None:
    reset_graph_state()
    add_graph_edge_owned("node:attention", "tag:execution", edge_type="tag", weight=1.0)

    first = graph.propagate_graph_attention("node:attention", half_life=0.001)
    time.sleep(0.02)
    second = graph.propagate_graph_attention("node:attention", half_life=0.001)

    assert first == second


def test_stage1186_graph_attention_does_not_create_missing_nodes_while_scoring() -> None:
    reset_graph_state()
    add_graph_edge_owned("node:attention", "tag:execution", edge_type="tag", weight=1.0)
    before = set(graph_snapshot())

    assert graph.propagate_graph_attention("node:attention") >= 0.0

    after = set(graph_snapshot())
    assert after == before
    assert graph_has_node("tag:execution")


def test_stage1186_graph_attention_source_has_no_wall_clock_or_score_time_mutation() -> None:
    source = _function_source("propagate_graph_attention")

    assert "time.time" not in source
    assert "ensure_graph_node(" not in source
    assert "sorted(edges, key=safe_graph_text)" in source
    assert "_owned_mapping_get(data, 'edges', ())" in source
