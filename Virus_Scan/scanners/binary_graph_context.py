"""Scanner-owned read-only graph context helpers for binary heuristics."""
from __future__ import annotations

from typing import Literal

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_plain_instance_dict

BinaryEdgeProbeStatus = Literal["absent", "present", "empty", "probe_error"]
BinaryEdgeAccessorStatus = Literal["absent", "present", "probe_error"]
_EDGE_MISSING = object()


def _edge_names() -> tuple[str, ...]:
    return ("edges", "out_edges", "in_edges", "neighbors", "links")


def _edge_value_present(value: object) -> tuple[BinaryEdgeProbeStatus, bool]:
    """Classify edge containers without invoking caller-owned truthiness."""
    if value is None:
        return ("empty", False)
    if type(value) in (tuple, list, set, frozenset):
        return (("present", True) if len(value) > 0 else ("empty", False))
    if type(value) is dict:
        return (("present", True) if len(value) > 0 else ("empty", False))
    return ("probe_error", False)


def _class_edge_accessor_status(node: object) -> BinaryEdgeAccessorStatus:
    try:
        class_dict = type.__getattribute__(type(node), "__dict__")
    except (AttributeError, TypeError):
        return "probe_error"
    items = no_hook_mapping_items(class_dict)
    if items is None:
        return "probe_error"
    edge_names = set(_edge_names())
    for name, _value in items:
        if type(name) is str and name in edge_names:
            return "present"
    return "absent"


def _plain_node_edge_values(node: object) -> tuple[object, ...] | None:
    data = no_hook_plain_instance_dict(node)
    if data is None:
        return None
    values = [dict.get(data, name, _EDGE_MISSING) for name in _edge_names()]
    return tuple(values)


def binary_node_edge_status(node: object) -> tuple[BinaryEdgeProbeStatus, bool]:
    """Return explicit graph-edge probe status without hiding probe failures.

    A callable graph accessor can fail for malformed/foreign graph objects.  That
    state is distinct from a real node with no edges, so callers must not convert
    probe failure into a clean ``no edges`` result.
    """
    if node is None:
        return ("absent", False)
    if type(node) is dict:
        for key in _edge_names():
            status, present = _edge_value_present(dict.get(node, key))
            if status == "present":
                return ("present", present)
            if status == "probe_error":
                return ("probe_error", False)
        return ("empty", False)
    edge_values = _plain_node_edge_values(node)
    if edge_values is None:
        return ("probe_error", False)
    edge_accessor_status = _class_edge_accessor_status(node)
    if edge_accessor_status == "probe_error":
        return ("probe_error", False)
    if edge_accessor_status == "present" and all(value is _EDGE_MISSING for value in edge_values):
        return ("probe_error", False)
    probe_status: BinaryEdgeProbeStatus = "empty"
    for value in edge_values:
        if value is _EDGE_MISSING:
            continue
        status, _ = _edge_value_present(value)
        if status == "present":
            return ("present", True)
        if status == "probe_error":
            probe_status = "probe_error"
    if probe_status == "probe_error":
        return ("probe_error", False)
    return ("empty", False)


def binary_node_has_edges(node: object) -> bool:
    """Best-effort read-only edge check for callers that need a boolean."""
    status, has_edges = binary_node_edge_status(node)
    return bool(status == "present" and has_edges)


__all__ = ("BinaryEdgeAccessorStatus", "BinaryEdgeProbeStatus", "binary_node_edge_status", "binary_node_has_edges")
