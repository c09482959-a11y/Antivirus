"""Shared immutable API call-graph projection contract."""

from __future__ import annotations

from types import MappingProxyType
from typing import Iterable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_optional_sequence_items, no_hook_text

_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))


def _safe_api_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_api_call_text",
        unsupported_reason="unsafe_api_call_text_rejected",
    )
    return text.strip() if reason == "" else ""


def _safe_mapping_items(value: object) -> tuple[tuple[object, object], ...]:
    if value is None:
        return ()
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    return items if items is not None else ()


def immutable_api_call_graph(api_sequence: Iterable[object] | None) -> Mapping[str, tuple[str, ...]]:
    """Return deterministic immutable adjacency from an ordered API sequence."""
    sequence = tuple(text for item in no_hook_optional_sequence_items(api_sequence) if (text := _safe_api_text(item)))
    graph: dict[str, set[str]] = {}
    for index in range(len(sequence) - 1):
        source = sequence[index]
        target = sequence[index + 1]
        graph.setdefault(source, set()).add(target)
    return MappingProxyType({source: tuple(sorted(graph[source])) for source in sorted(graph)})


def api_call_graph_features(call_graph: Mapping[str, Iterable[object]] | None) -> dict[str, int | float]:
    """Return deterministic pure API-call graph feature counts."""
    items = _safe_mapping_items(call_graph)
    nodes = len(items)
    edges = sum(len(no_hook_optional_sequence_items(value)) for _source, value in items)
    density = edges / (nodes + 1e-6)
    return {'nodes': nodes, 'edges': edges, 'density': density}


__all__ = ('immutable_api_call_graph', 'api_call_graph_features')
