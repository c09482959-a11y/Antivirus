from __future__ import annotations

import hashlib

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.cluster_state import ClusterStateNotConfigured, cluster_state
from Virus_Scan.runtime.graph_state import (
    graph_has_node,
    graph_node_snapshot,
    graph_vector_node_key,
)
from Virus_Scan.models.graph.common import (
    ATTACK_GRAPH,
    MIN_CLUSTER_SIZE,
    safe_graph_text_with_reason,
    graph_first_reason,
    graph_owned_key_matches,
    graph_unit_interval,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message
from Virus_Scan.models.graph.state import add_graph_edge

def _owned_mapping_get(value: object, name: object, default: object=()) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if graph_owned_key_matches(key, name):
            return item
    return default

def _owned_mapping_items(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    return items

def _graph_projection_text(value: object, reason: object) -> object:
    text, text_reason = safe_graph_text_with_reason(value, reason)
    if text_reason or text == '':
        return '', text_reason or reason
    return text, ''


def _graph_projection_values(value: object, reason: object) -> object:
    if value is None:
        return frozenset()
    if type(value) in (str, bytes, bytearray):
        candidates = (value,)
    elif type(value) is tuple:
        candidates = value
    elif type(value) in (list, set, frozenset):
        candidates = tuple(value)
    else:
        return frozenset()
    out = set()
    for item in candidates:
        text, text_reason = _graph_projection_text(item, reason)
        if text_reason == '':
            out.add(text)
    return frozenset(out)


def _graph_projection_label(prefix: object, value: object, reason: object) -> object:
    text, text_reason = _graph_projection_text(value, reason)
    if text_reason:
        return prefix + reason
    return prefix + text


def _cluster_node_key(node: object) -> object:
    key_text, key_reason = _graph_projection_text(graph_vector_node_key(node), 'cluster_node_key_unavailable')
    if key_reason == '':
        return key_text
    node_text, node_reason = _graph_projection_text(node, 'cluster_node_unavailable')
    if node_reason == '':
        return node_text
    return ''


def _cluster_id_text(value: object) -> object:
    text, reason = _graph_projection_text(value, 'cluster_id_unavailable')
    if reason:
        return '', reason
    return text, ''

def _runtime_cluster_members_for_node(node: object) -> object:
    """Read runtime-owned cluster assignment without importing clustering internals."""
    try:
        state = cluster_state()
    except ClusterStateNotConfigured:
        return None, frozenset(), 'runtime_cluster_state_not_configured'
    key = _cluster_node_key(node)
    if key == '':
        return None, frozenset(), 'cluster_node_key_unavailable'
    try:
        with state.lock:
            cid = state.node_cluster_map.get(key)
            cid_text, cid_reason = _cluster_id_text(cid) if cid is not None else ('', 'cluster_unavailable')
            if cid_reason or cid_text == '':
                return None, frozenset(), 'cluster_unavailable'
            members = set()
            for store in (state.malicious_clusters, state.benign_clusters, state.mixed_clusters):
                members.update(_graph_projection_values(_owned_mapping_get(store, cid_text, ()), 'cluster_members_unavailable'))
            meta = _owned_mapping_get(state.cluster_metadata, cid_text, {})
            if no_hook_mapping_items(meta) is None:
                meta = {}
            members.update(_graph_projection_values(_owned_mapping_get(meta, 'members', ()), 'cluster_meta_members_unavailable'))
            members.add(key)
            return cid_text, frozenset(members), None
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(graph_exception_message('runtime cluster state read failed for graph reinforcement: ', exc))
        return None, frozenset(), 'runtime_cluster_state_read_failed'

def reinforce_graph_with_cluster(node: object) -> object:
    """Add deterministic cluster membership evidence to graph from runtime cluster state."""
    cid, members, reason = _runtime_cluster_members_for_node(node)
    if cid is None:
        return {'reinforced': False, 'reason': graph_first_reason(reason, default='cluster_unavailable')}
    confidence = graph_unit_interval(len(members) / max(1, MIN_CLUSTER_SIZE * 2), reason='cluster_graph_confidence_unavailable')[0]
    cid_text = cid
    add_graph_edge(
        node,
        _graph_projection_label('cluster:', cid_text, 'graph_cluster_label_unavailable'),
        edge_type='cluster_explanation',
        weight=1.0 + confidence,
    )
    return {
        'reinforced': True, 'cluster': cid_text, 'confidence': confidence,
        'score_influence': False,
    }

def reinforce_cluster_with_graph(node: object) -> object:
    """Project graph evidence onto cluster graph nodes without mutating cluster state."""
    cid, _, reason = _runtime_cluster_members_for_node(node)
    if cid is None:
        return {'reinforced': False, 'reason': graph_first_reason(reason, default='cluster_unavailable')}
    if not graph_has_node(node):
        return {'reinforced': False, 'reason': 'graph_unavailable'}
    data = graph_node_snapshot(node)
    if data is None:
        data = {}
    graph_strength = graph_unit_interval(len(_owned_mapping_get(data, 'edges', ())) / 25.0, reason='cluster_graph_strength_unavailable')[0]
    cid_text = cid
    add_graph_edge(
        _graph_projection_label('cluster:', cid_text, 'graph_cluster_label_unavailable'),
        node,
        edge_type='graph_member_explanation',
        weight=1.0 + graph_strength,
    )
    return {
        'reinforced': True, 'cluster': cid_text, 'graph_strength': graph_strength,
        'score_influence': False,
    }

def propagate_cluster_influence(node: object, tags: object=None) -> None:
    """
    Safe cluster -> graph influence propagation.

    Cluster membership is read from the runtime cluster-state owner.  The graph
    model may project that evidence into graph edges, but it must not use stale
    runtime config snapshots or mutate clustering state directly.
    """
    cid, members, _reason = _runtime_cluster_members_for_node(node)
    if cid is None:
        return
    if len(members) < MIN_CLUSTER_SIZE:
        return
    cid_text = cid
    add_graph_edge(
        node,
        _graph_projection_label('cluster:', cid_text, 'graph_cluster_label_unavailable'),
        edge_type='cluster_explanation',
        weight=1.5,
    )
    node_key = _cluster_node_key(node)
    for m in sorted(members)[:25]:
        if m != node_key:
            peer_digest = hashlib.md5(str.encode(m), usedforsecurity=False).hexdigest()[:12]
            add_graph_edge(
                node,
                _graph_projection_label('cluster_peer:', peer_digest, 'graph_cluster_label_unavailable'),
                edge_type='cluster_peer_explanation',
                weight=0.4,
            )
    tag_set = set(_graph_projection_values(tags, 'cluster_influence_tags_unavailable'))
    for phase, data in _owned_mapping_items(ATTACK_GRAPH):
        for attack_node in _owned_mapping_get(data, 'nodes', []):
            attack_text, attack_reason = _graph_projection_text(attack_node, 'cluster_attack_node_unavailable')
            phase_text, phase_reason = _graph_projection_text(phase, 'cluster_attack_phase_unavailable')
            if attack_reason == '' and phase_reason == '' and attack_text in tag_set:
                add_graph_edge(
                    node,
                    _graph_projection_label('attack:', attack_text, 'graph_cluster_label_unavailable'),
                    edge_type='cluster_attack_explanation',
                    weight=2.0,
                )

__all__ = (
    'reinforce_graph_with_cluster',
    'reinforce_cluster_with_graph',
    'propagate_cluster_influence',
)
