"""Deterministic runtime support for the canonical graph-attention owner."""
from __future__ import annotations

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.graph_state import graph_has_node
from Virus_Scan.runtime.model_state import runtime_model_mapping_snapshot
from Virus_Scan.models.graph.common import (
    GLOBAL_TAG_BASELINE,
    coerce_graph_event_time,
    safe_graph_text,
)
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message
from Virus_Scan.models.graph.contracts import GRAPH_RISK_POLICY
from Virus_Scan.models.graph.state import get_graph_node
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items


def _owned_mapping_get(value: object, name: object, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if type(key) is str and type(name) is str and str.__str__(key) == str.__str__(name):
            return item
    return default


def graph_tag_baseline_snapshot() -> object:
    baseline = runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE")
    return baseline if len(baseline) > 0 else GLOBAL_TAG_BASELINE


def coerce_graph_attention_time(value: object) -> object:
    numeric, reason = coerce_graph_event_time(value)
    return (None, reason) if reason else (numeric, "")


def graph_attention_reference_time(start_node: object, depth: object = 2) -> object:
    """Return a deterministic snapshot-local time anchor without mutation."""
    reference = 0.0
    visited = set()
    stack = [(start_node, 0)]
    max_depth = depth if type(depth) is int and not isinstance(depth, bool) else 1
    max_depth = min(8, max(0, max_depth))
    work = 0
    while stack and work < GRAPH_RISK_POLICY.maximum_attention_work:
        node, current_depth = stack.pop()
        work += 1
        if node in visited or current_depth > max_depth:
            continue
        visited.add(node)
        data = get_graph_node(node)
        if data is None:
            continue
        try:
            last_seen = _owned_mapping_get(data, "last_seen")
            if last_seen is not None:
                numeric, reason = coerce_graph_attention_time(last_seen)
                if reason == "" and numeric is not None:
                    reference = max(reference, numeric)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            log_error(graph_exception_message("graph reference last_seen coercion failed: ", exc))
        edge_time = _owned_mapping_get(data, "edge_time", {})
        for edge in sorted(_owned_mapping_get(data, "edges", ()), key=safe_graph_text):
            try:
                raw_time = _owned_mapping_get(edge_time, edge)
                if raw_time is not None:
                    numeric, reason = coerce_graph_attention_time(raw_time)
                    if reason == "" and numeric is not None:
                        reference = max(reference, numeric)
            except RECOVERABLE_RUNTIME_ERRORS as exc:
                log_error(graph_exception_message("graph reference edge time coercion failed: ", exc))
            if graph_has_node(edge):
                stack.append((edge, current_depth + 1))
    return reference


__all__ = (
    "coerce_graph_attention_time",
    "graph_attention_reference_time",
    "graph_tag_baseline_snapshot",
)
