from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    decay_graph_weights_owned,
    ensure_graph_node_owned,
    graph_node_snapshot,
    prune_graph_owned,
)
from Virus_Scan.models.graph.common import (
    graph_finite_float,
)
from Virus_Scan.models.graph.cache import GRAPH_RISK_CACHE


def _graph_snapshot_frozenset(value: object) -> frozenset[object]:
    if isinstance(value, (frozenset, set, tuple, list)):
        return frozenset(value)
    return frozenset()


def add_graph_edge(
    src: object,
    dst: object,
    edge_type: object = None,
    weight: object = 1.0,
    *,
    evidence_id: object = None,
    confidence: object = 1.0,
    direction: object = "outbound",
) -> None:
    """Canonical graph edge writer owned by runtime.graph_state."""
    add_graph_edge_owned(
        src,
        dst,
        edge_type=edge_type,
        weight=weight,
        evidence_id=evidence_id,
        confidence=confidence,
        direction=direction,
    )

def ensure_graph_node(node: object) -> None:
    ensure_graph_node_owned(node)

def get_graph_node(node: object) -> object:
    data = graph_node_snapshot(node)
    if data is None:
        return None
    return MappingProxyType({
        'snapshot_version': data.get('snapshot_version'),
        'snapshot_digest': data.get('snapshot_digest'),
        'node_id': data.get('node_id'),
        'node_type': data.get('node_type'),
        'created_ordinal': data.get('created_ordinal', 0),
        'update_ordinal': data.get('update_ordinal', 0),
        'edge_records': tuple(data.get('edge_records', ())) if type(data.get('edge_records', ())) is tuple else (),
        'edges': _graph_snapshot_frozenset(data.get('edges', frozenset())),
        'edge_time': data.get('edge_time', MappingProxyType({})),
        'weights': data.get('weights', MappingProxyType({})),
        'types': data.get('types', MappingProxyType({})),
        'edge_evidence_ids': data.get('edge_evidence_ids', MappingProxyType({})),
        'edge_confidence': data.get('edge_confidence', MappingProxyType({})),
        'edge_directions': data.get('edge_directions', MappingProxyType({})),
        'risk': graph_finite_float(data.get('risk', 0.0), minimum=0.0)[0],
        'last_seen': data.get('last_seen'),
        'attention': graph_finite_float(data.get('attention', 0.0), minimum=0.0, maximum=1.0)[0],
        'risk_unavailable_reason': data.get('risk_unavailable_reason'),
        'attention_unavailable_reason': data.get('attention_unavailable_reason'),
        'weight_unavailable_reasons': data.get('weight_unavailable_reasons', MappingProxyType({})),
        'tags': _graph_snapshot_frozenset(data.get('tags', frozenset())),
        'tag_evidence_records': tuple(data.get('tag_evidence_records', ()))
        if type(data.get('tag_evidence_records', ())) in (tuple, list)
        else (),
        'tags_unavailable_reason': data.get('tags_unavailable_reason'),
        'tag_evidence_unavailable_reason': data.get('tag_evidence_unavailable_reason'),
        'context': data.get('context', MappingProxyType({})),
        'context_baseline': data.get('context_baseline'),
        'current_scan_cycle_guard': data.get('current_scan_cycle_guard'),
    })

def graph_similarity(g1: object, g2: object) -> object:
    edges1 = {(a, b) for a in g1 for b in g1[a]}
    edges2 = {(a, b) for a in g2 for b in g2[a]}
    if not edges1 or not edges2:
        return 0.0
    return len(edges1 & edges2) / len(edges1 | edges2)

def enforce_graph_decay(decay: object=0.995, min_weight: object=0.01) -> None:
    """Apply deterministic graph-weight decay through the runtime graph owner."""
    decay_graph_weights_owned(decay=decay, min_weight=min_weight)
    GRAPH_RISK_CACHE.clear()

def prune_graph(max_nodes: object=50000, max_edges_per_node: object=200) -> None:
    prune_graph_owned(max_nodes=max_nodes, max_edges_per_node=max_edges_per_node)
    GRAPH_RISK_CACHE.clear()

__all__ = ('add_graph_edge', 'enforce_graph_decay', 'ensure_graph_node', 'get_graph_node', 'graph_similarity', 'prune_graph')
