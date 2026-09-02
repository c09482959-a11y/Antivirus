"""Test-only graph corruption helpers.

Production code must write graph state through the runtime-owned mutation APIs.
These helpers exist only so hostile-boundary tests can inject malformed runtime
node fields without re-exporting the historical HYBRID_GRAPH mutable alias.
"""
from __future__ import annotations

from typing import Any

from Virus_Scan.runtime.graph_state import ensure_graph_node_owned, graph_owner, graph_vector_node_key


def corrupt_graph_node_for_test(node: Any, **values: Any) -> str:
    """Inject raw node values for hostile-boundary tests only."""
    node_key = graph_vector_node_key(node)
    ensure_graph_node_owned(node_key)
    graph_owner().graph.setdefault(node_key, {}).update(values)
    return node_key


def clear_graph_node_for_test(node: Any) -> str:
    """Replace a node payload with an empty raw mapping for boundary tests only."""
    node_key = graph_vector_node_key(node)
    ensure_graph_node_owned(node_key)
    graph_owner().graph[node_key] = {}
    return node_key


def remove_graph_node_fields_for_test(node: Any, *fields: str) -> str:
    """Remove raw node fields for hostile-boundary tests only."""
    node_key = graph_vector_node_key(node)
    ensure_graph_node_owned(node_key)
    data = graph_owner().graph.setdefault(node_key, {})
    for field in fields:
        data.pop(field, None)
    return node_key


__all__ = (
    'clear_graph_node_for_test',
    'corrupt_graph_node_for_test',
    'remove_graph_node_fields_for_test',
)
