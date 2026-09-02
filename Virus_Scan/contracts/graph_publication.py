"""Immutable graph-publication request contracts shared across domains."""

from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from typing import Mapping

GraphPublicationEdge = tuple[str, str, str, float]


def _graph_publication_text(value: object) -> str:
    if value is None:
        return ""
    text, reason = no_hook_text(
        value,
        missing_reason="graph_publication_identity_unavailable",
        unsupported_reason="unsupported_graph_publication_identity",
    )
    if reason == "" and text != "":
        return text
    return reason + ":" + no_hook_type_name(value)


def _graph_publication_items(values: object) -> tuple[object, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)) or type(values) is bytearray:
        return (values,)
    if type(values) is tuple:
        return values
    if type(values) is list:
        return tuple(values)
    if type(values) in (set, frozenset):
        return tuple(sorted(values, key=_graph_publication_text))
    return ("graph_publication_iterable_unavailable",)


def _graph_publication_mapping_items(value: object) -> tuple[tuple[object, object], ...]:
    if value is None:
        return ()
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is not None:
        return items
    return (("graph_publication_mapping_unavailable", ("graph_publication_iterable_unavailable",)),)


def api_graph_publication_edges(
    node: object,
    api_calls: object,
    api_tags: object,
    call_graph: Mapping[object, object] | None,
) -> tuple[GraphPublicationEdge, ...]:
    """Return immutable API graph-publication edge requests.

    Scanner and detection callers may observe API relationships, but neither
    mutates graph state. Publication owners consume this immutable contract.
    """
    edges: list[GraphPublicationEdge] = []
    node_text = _graph_publication_text(node)
    if node_text:
        edges.extend(
            (node_text, "api:" + _graph_publication_text(api), "api", 1.0)
            for api in _graph_publication_items(api_calls)
        )
        edges.extend(
            (node_text, "api_tag:" + _graph_publication_text(tag), "api_tag", 1.5)
            for tag in _graph_publication_items(api_tags)
        )
    for source, targets in _graph_publication_mapping_items(call_graph):
        source_text = _graph_publication_text(source)
        edges.extend(
            ("api:" + source_text, "api:" + _graph_publication_text(target), "api_sequence", 1.25)
            for target in _graph_publication_items(targets)
        )
    return tuple(edges)


__all__ = ("GraphPublicationEdge", "api_graph_publication_edges")
