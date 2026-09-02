from __future__ import annotations

from Virus_Scan.models.graph.common_text_boundaries import graph_reasoned_text, safe_graph_sequence


def graph_relationship_text(value: object, reason: object) -> object:
    text, text_reason = graph_reasoned_text(value, reason)
    return text, text_reason


def graph_relationship_sequence(value: object, reason: object) -> object:
    values, sequence_reason = safe_graph_sequence(value, reason)
    return values, sequence_reason


def graph_relationship_phase_hit_text(phase: object) -> object:
    return str.__add__('phase:', phase)


def graph_relationship_mapping_sort_key(pair: object) -> object:
    key, _item = pair
    text, _reason = graph_relationship_text(key, 'graph_relationship_key_unavailable')
    return text


def graph_relationship_tag_contains_node(tagset: object, node_text: object) -> object:
    return any(type(tag) is str and str.__contains__(tag, node_text) for tag in tagset)


def graph_relationship_set_sort_key(value: object) -> object:
    text, _reason = graph_relationship_text(value, 'graph_relationship_set_item_unavailable')
    return text


__all__ = (
    'graph_relationship_mapping_sort_key',
    'graph_relationship_phase_hit_text',
    'graph_relationship_sequence',
    'graph_relationship_set_sort_key',
    'graph_relationship_tag_contains_node',
    'graph_relationship_text',
)
