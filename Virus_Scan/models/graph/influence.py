from __future__ import annotations

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.graph_state import graph_has_node, update_graph_node_owned
from Virus_Scan.models.graph.common import graph_finite_float, safe_graph_text
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.models.graph.attention import (
    compute_attention_weights,
    graph_attention_evidence,
)
from Virus_Scan.models.graph.state import ensure_graph_node, enforce_graph_decay


def _ranked_attention_weight_items(weights: object) -> object:
    items = no_hook_mapping_items(weights)
    if items is None:
        return ()
    ranked = []
    for node_key, raw_weight in items:
        weight, weight_reason = graph_finite_float(
            raw_weight,
            default=0.0,
            minimum=0.0,
            reason='graph_attention_weight_unavailable',
        )
        if weight_reason != '':
            continue
        ranked.append((node_key, weight))
    return tuple(sorted(
        ranked,
        key=lambda item: (item[1], safe_graph_text(item[0])),
        reverse=True,
    ))


def explain_graph_influence(node: object) -> object:
    """Return the top bounded attention contributors."""
    if not graph_has_node(node):
        return []
    weights = compute_attention_weights(node)
    return list(_ranked_attention_weight_items(weights)[:10])


def integrate_graph_intelligence(node: object, tags: object = None) -> None:
    """Update attention without creating a current-scan graph/cluster cycle.

    Cluster projections remain explicit explanation operations owned by
    ``cluster_projection.py``. They are not invoked by the graph scoring update
    path and their edge types are excluded from graph risk and attention.
    """
    del tags
    ensure_graph_node(node)
    enforce_graph_decay()
    try:
        evidence = graph_attention_evidence(node)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(
            'graph attention propagation failed with canonical graph scoring authority: '
            + no_hook_type_name(exc)
        )
        update_graph_node_owned(
            node,
            attention_unavailable_reason='graph_attention_computation_failed',
            current_scan_cycle_guard='graph_score_excludes_current_cluster',
        )
        return
    if evidence.ready:
        update_graph_node_owned(
            node,
            attention=evidence.value,
            current_scan_cycle_guard='graph_score_excludes_current_cluster',
            attention_contract_version=evidence.version,
        )
    else:
        update_graph_node_owned(
            node,
            attention_unavailable_reason=evidence.unavailable_reason,
            current_scan_cycle_guard='graph_score_excludes_current_cluster',
            attention_contract_version=evidence.version,
        )


__all__ = ('explain_graph_influence', 'integrate_graph_intelligence')
