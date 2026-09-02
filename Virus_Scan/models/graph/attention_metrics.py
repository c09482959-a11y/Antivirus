from __future__ import annotations

from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.models.graph.common import (
    graph_owned_key_matches,
    graph_unit_interval,
    record_graph_input_degraded,
)

GRAPH_ATTENTION_UNAVAILABLE_SCORE = 0.0


def _owned_mapping_get(value: object, name: object, default: object=None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if graph_owned_key_matches(key, name):
            return item
    return default


def attention_lookup_result(attention: object, edge: object) -> object:
    """Return bounded graph attention plus explicit unavailable reason."""
    if no_hook_mapping_items(attention) is None:
        return GRAPH_ATTENTION_UNAVAILABLE_SCORE, 'graph_attention_mapping_unavailable'
    metric, reason = graph_unit_interval(
        _owned_mapping_get(attention, edge, GRAPH_ATTENTION_UNAVAILABLE_SCORE),
        reason='graph_attention_weight_unavailable',
    )
    if reason != '':
        return GRAPH_ATTENTION_UNAVAILABLE_SCORE, reason
    return metric, ''


def safe_attention_lookup(attention: object, edge: object) -> object:
    """Bounded attention lookup for graph propagation from owned mappings."""
    metric, reason = attention_lookup_result(attention, edge)
    if reason != '':
        record_graph_input_degraded('graph_attention_lookup_unavailable', reason)
    return metric


__all__ = (
    'GRAPH_ATTENTION_UNAVAILABLE_SCORE',
    'attention_lookup_result',
    'safe_attention_lookup',
)
