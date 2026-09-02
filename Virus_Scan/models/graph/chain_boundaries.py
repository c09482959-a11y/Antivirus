"""Primitive no-hook materialization boundaries for graph-chain models."""

from __future__ import annotations

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
)
from Virus_Scan.models.graph.common import graph_finite_float, safe_graph_text_with_reason



def first_chain_config_value(mapping: object, names: object, default: object) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for name in names:
        for key, value in items:
            if type(key) is str and str.__str__(key) == name and value is not None:
                return value
    return default


def safe_chain_weight(value: object) -> float:
    numeric, reason = graph_finite_float(
        value, default=8.0, minimum=0.0, reason='graph_chain_weight_unavailable',
    )
    return 8.0 if reason != '' else numeric



def safe_graph_values(value: object) -> tuple[object, ...]:
    """Return graph traversal values without invoking caller-owned iteration."""
    if value is None:
        return ()
    if type(value) in (str, bytes, bytearray):
        return (value,)
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value)
    return ()


def safe_mapping_items(value: object) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(value)
    return () if items is None else items


def behavior_chain_name(index: object) -> str:
    return 'behavior_chain_' + int.__str__(index)


def chain_exact_text(value: object, reason: object) -> tuple[str, str]:
    text, text_reason = safe_graph_text_with_reason(value, reason)
    return ('', text_reason) if text_reason else (text, '')


def chain_name(value: object, index: object) -> str:
    text, reason = chain_exact_text(value, 'graph_chain_name_unavailable')
    return behavior_chain_name(index) if reason or text == '' else text


def chain_ordered_texts(values: object, reason: object) -> tuple[str, ...]:
    out = []
    for value in values:
        text, text_reason = chain_exact_text(value, reason)
        if not text_reason and text != '':
            out.append(text)
    return tuple(sorted(set(out), key=str.__str__))


__all__ = (
    'behavior_chain_name',
    'chain_exact_text',
    'chain_name',
    'chain_ordered_texts',
    'first_chain_config_value',
    'safe_chain_weight',
    'safe_graph_values',
    'safe_mapping_items',
)
