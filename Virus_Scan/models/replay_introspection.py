"""Replay lineage introspection, budgets, and integrity helpers."""
from __future__ import annotations
from dataclasses import dataclass, field, replace
from typing import Iterable
import math

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text


_REPLAY_TEXT_SCALAR_TYPES = (int, float, bool)
_REPLAY_MISSING_VALUE = None


def _replay_detached_text(value: object) -> tuple[str, bool]:
    """Return detached replay text without invoking caller-owned ``__str__``.

    Replay introspection output is consumed by governance/final-JSON-style
    evidence paths.  Unsupported objects must not be coerced through arbitrary
    ``__str__`` implementations because that can crash, mutate caller state, or
    hide missing evidence behind clean empty strings.
    """
    if value is None:
        return "None", True
    if type(value) is bool:
        return ("True" if value else "False"), True
    text, reason = no_hook_text(
        value,
        missing_reason="missing_replay_text",
        unsupported_reason="unsupported_replay_text",
    )
    if reason == "":
        return text, True
    return "", False


def _safe_replay_text(value: object, default: str = "") -> str:
    """Return exact built-in replay text without caller-owned string hooks."""
    text, readable = _replay_detached_text(value)
    if not readable:
        return ''.join((str.__str__(default),)) if isinstance(default, str) else ''
    return text


def _first_replay_text(*values: str) -> str:
    for value in values:
        text = _safe_replay_text(value)
        if text != "":
            return text
    return ""


def _replay_introspection_error(*parts: str) -> str:
    return ":".join(parts)


def _replay_introspection_count(value: int) -> str:
    return int.__str__(value)


def _replay_mapping_items(value: object) -> tuple[tuple[object, object], ...]:
    return no_hook_mapping_items(value, allow_dict_subclass=True) or ()


def _replay_mapping_get(value: object, key: str, default: object = None) -> object:
    for item_key, item_value in _replay_mapping_items(value):
        if type(item_key) is str and str.__eq__(item_key, key) is True:
            return item_value
    return default


def _replay_primitive_text(value: object) -> str | None:
    if type(value) is str:
        return str.strip(str.__str__(value))
    if type(value) is not bytes:
        return _REPLAY_MISSING_VALUE
    try:
        return bytes.decode(value, "utf-8", "replace").strip()
    except RECOVERABLE_RUNTIME_ERRORS:
        return _REPLAY_MISSING_VALUE


def _replay_float_candidate(value: object) -> float | None:
    if type(value) is int:
        return float(value)
    if type(value) is float:
        return value
    text = _replay_primitive_text(value)
    if text is None or text == "":
        return _REPLAY_MISSING_VALUE
    try:
        return float(text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _REPLAY_MISSING_VALUE


def _safe_replay_float(value: object, default: float = 0.0) -> float:
    default_value = default if type(default) is float and math.isfinite(default) else 0.0
    numeric = None if value is None or type(value) is bool else _replay_float_candidate(value)
    return numeric if numeric is not None and math.isfinite(numeric) else default_value


def _replay_positive_int_candidate(value: object) -> tuple[int | None, bool]:
    if type(value) is bool:
        return _REPLAY_MISSING_VALUE, False
    if type(value) is int:
        return value, value > 0
    if type(value) is float:
        valid = math.isfinite(value) and value.is_integer() and value > 0
        return (int(value), True) if valid else (None, False)
    text = _replay_primitive_text(value)
    if text is None or text == "":
        return _REPLAY_MISSING_VALUE, False
    try:
        parsed = int(text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _REPLAY_MISSING_VALUE, False
    return parsed, parsed > 0


def _safe_replay_positive_int(value: object, default: int) -> tuple[int, bool]:
    default_value = default if type(default) is int and default > 0 else 1
    if value is None:
        return default_value, True
    parsed, valid = _replay_positive_int_candidate(value)
    return (parsed, True) if valid and parsed is not None else (default_value, False)


def _safe_replay_tags(tags: object) -> tuple[str, ...]:
    if tags is None:
        return ()
    if type(tags) is str:
        return (_safe_replay_text(tags, "<unavailable_replay_tag>"),)
    if type(tags) is bytes:
        return (_safe_replay_text(tags, "<unavailable_replay_tag>"),)
    if type(tags) not in (list, tuple):
        return ("<unavailable_replay_tags>",)
    out: list[str] = []
    for item in tags:
        text = _safe_replay_text(item, "<unavailable_replay_tag>")
        if text:
            out.append(text)
    return tuple(out)


def _unavailable_replay_node(reason: str) -> "ReplayNode":
    return ReplayNode(
        "<unavailable_replay_node>",
        None,
        ("replay_nodes_unavailable", reason),
        0.0,
        "replay_introspection",
        reason,
    )


def _safe_replay_nodes(nodes: object) -> list["ReplayNode"]:
    if nodes is None:
        return []
    if isinstance(nodes, ReplayNode):
        return [nodes]
    if type(nodes) not in (list, tuple):
        return [_unavailable_replay_node("unsupported_replay_node_source")]
    return [node for node in nodes if isinstance(node, ReplayNode)]


@dataclass(frozen=True)
class ReplayNode:
    node_id: str
    parent_id: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    influence: float = 0.0
    origin: str = ""
    rationale: str = ""

    def __post_init__(self) -> None:
        node_id = _safe_replay_text(self.node_id, "<unavailable_replay_node>")
        parent_id = None if self.parent_id is None else _safe_replay_text(self.parent_id, "<unavailable_replay_parent>")
        object.__setattr__(self, "node_id", node_id)
        object.__setattr__(self, "parent_id", parent_id)
        object.__setattr__(self, "tags", _safe_replay_tags(self.tags))
        object.__setattr__(self, "influence", _safe_replay_float(self.influence))
        object.__setattr__(self, "origin", _safe_replay_text(self.origin))
        object.__setattr__(self, "rationale", _safe_replay_text(self.rationale))


@dataclass(frozen=True)
class ReplayBudget:
    max_depth: int = 16
    max_fanout: int = 128
    max_nodes: int = 8192
    min_influence_to_keep: float = 0.01


def lineage_depth(nodes: list[ReplayNode]) -> int:
    safe_nodes = _safe_replay_nodes(nodes)
    by_id = {n.node_id: n for n in safe_nodes}

    def depth(n: ReplayNode, seen: set[str] | None = None) -> int:
        seen_ids = set() if seen is None else set(seen)
        if n.node_id in seen_ids or n.parent_id is None or n.parent_id not in by_id:
            return 1
        seen_ids.add(n.node_id)
        return 1 + depth(by_id[n.parent_id], seen_ids)

    return max([depth(n) for n in safe_nodes] or [0])


def replay_influence_graph(nodes: Iterable[ReplayNode]) -> dict[str, object]:
    ns = _safe_replay_nodes(nodes)
    edges = []
    attribution = {}
    for n in sorted(ns, key=lambda x: x.node_id):
        influence = _safe_replay_float(n.influence)
        if n.parent_id is not None and n.parent_id != "":
            edges.append({"parent": n.parent_id, "child": n.node_id, "influence": influence})
        attribution[n.node_id] = {
            "origin": n.origin,
            "rationale": n.rationale,
            "tags": sorted(set(_safe_replay_tags(n.tags))),
            "influence": influence,
            "parent": n.parent_id,
        }
    return {"nodes": len(ns), "edges": edges, "attribution": attribution, "depth": lineage_depth(ns)}


def compress_replay_nodes(nodes: Iterable[ReplayNode]) -> list[ReplayNode]:
    merged: dict[tuple[str, str | None], ReplayNode] = {}
    for n in _safe_replay_nodes(nodes):
        key = (n.node_id, n.parent_id)
        cur = merged.get(key)
        if cur is None:
            merged[key] = ReplayNode(n.node_id, n.parent_id, tuple(sorted(set(_safe_replay_tags(n.tags)))), _safe_replay_float(n.influence), n.origin, n.rationale)
        else:
            merged[key] = replace(
                cur,
                tags=tuple(sorted(set(_safe_replay_tags(cur.tags)).union(_safe_replay_tags(n.tags)))),
                influence=max(_safe_replay_float(cur.influence), _safe_replay_float(n.influence)),
                origin=_first_replay_text(cur.origin, n.origin),
                rationale=_first_replay_text(cur.rationale, n.rationale),
            )
    return [merged[k] for k in sorted(merged)]


def garbage_collect_replay(nodes: Iterable[ReplayNode], *, budget: ReplayBudget | None = None) -> list[ReplayNode]:
    active_budget = budget if budget is not None else ReplayBudget()
    threshold = _safe_replay_float(active_budget.min_influence_to_keep, 0.01)
    kept = [n for n in compress_replay_nodes(nodes) if abs(_safe_replay_float(n.influence)) >= threshold or n.parent_id is None]
    kept.sort(key=lambda n: (-abs(_safe_replay_float(n.influence)), n.node_id))
    max_nodes, _max_nodes_valid = _safe_replay_positive_int(active_budget.max_nodes, 8192)
    return kept[:max_nodes]


def _replay_lineage_edges(
    safe_nodes: list[ReplayNode],
) -> tuple[dict[str, int], dict[str, str], list[str]]:
    fanout: dict[str, int] = {}
    parent_edges: dict[str, str] = {}
    errors: list[str] = []
    ids: set[str] = set()
    for node in safe_nodes:
        if node.node_id in ids:
            errors.append(_replay_introspection_error("duplicate_node", node.node_id))
        ids.add(node.node_id)
        if node.parent_id is not None and node.parent_id != "":
            fanout[node.parent_id] = fanout.get(node.parent_id, 0) + 1
            parent_edges[node.node_id] = node.parent_id
    return fanout, parent_edges, errors


def _replay_cycle_errors(parent_edges: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for child in sorted(parent_edges):
        seen: set[str] = set()
        current = child
        while current in parent_edges:
            if current in seen:
                errors.append(_replay_introspection_error("cycle", child))
                break
            seen.add(current)
            current = parent_edges[current]
    return errors


def _replay_budget_errors(
    safe_nodes: list[ReplayNode],
    max_depth: object,
    max_fanout: object,
    max_nodes: object,
    depth: int,
) -> tuple[int, int, list[str]]:
    errors: list[str] = []
    safe_max_depth, max_depth_valid = _safe_replay_positive_int(max_depth, 16)
    safe_max_fanout, max_fanout_valid = _safe_replay_positive_int(max_fanout, 128)
    if not max_depth_valid:
        errors.append("max_depth_limit_unavailable")
    if not max_fanout_valid:
        errors.append("max_fanout_limit_unavailable")
    if max_nodes is not None:
        safe_max_nodes, max_nodes_valid = _safe_replay_positive_int(max_nodes, 8192)
        if not max_nodes_valid:
            errors.append("max_nodes_limit_unavailable")
        elif len(safe_nodes) > safe_max_nodes:
            errors.append(
                "nodes_exceeded:"
                + _replay_introspection_count(len(safe_nodes))
                + ">"
                + _replay_introspection_count(safe_max_nodes)
            )
    if depth > safe_max_depth:
        errors.append(
            "depth_exceeded:"
            + _replay_introspection_count(depth)
            + ">"
            + _replay_introspection_count(safe_max_depth)
        )
    return safe_max_depth, safe_max_fanout, errors


def _replay_fanout_errors(fanout: dict[str, int], safe_max_fanout: int) -> list[str]:
    errors: list[str] = []
    for parent in sorted(fanout):
        count = fanout[parent]
        if count > safe_max_fanout:
            errors.append(
                "fanout_exceeded:"
                + parent
                + ":"
                + _replay_introspection_count(count)
                + ">"
                + _replay_introspection_count(safe_max_fanout)
            )
    return errors


def validate_replay_lineage(nodes: list[ReplayNode], *, max_depth: int = 16, max_fanout: int = 128, max_nodes: int | None = None) -> dict[str, object]:
    safe_nodes = _safe_replay_nodes(nodes)
    fanout, parent_edges, errors = _replay_lineage_edges(safe_nodes)
    errors.extend(_replay_cycle_errors(parent_edges))
    depth = lineage_depth(safe_nodes)
    _safe_max_depth, safe_max_fanout, budget_errors = _replay_budget_errors(
        safe_nodes,
        max_depth,
        max_fanout,
        max_nodes,
        depth,
    )
    errors.extend(budget_errors)
    errors.extend(_replay_fanout_errors(fanout, safe_max_fanout))
    fanout_counts = tuple(dict.values(fanout))
    return {
        "ok": not errors,
        "errors": errors,
        "depth": depth,
        "fanout_max": max(fanout_counts or (0,)),
        "nodes": len(safe_nodes),
        "graph": replay_influence_graph(safe_nodes),
    }


def why_suspicious_report(nodes: Iterable[ReplayNode], *, node_id: str | None = None) -> dict[str, object]:
    graph = replay_influence_graph(nodes)
    requested_node_id = None if node_id is None else _safe_replay_text(node_id)
    if requested_node_id is not None and requested_node_id != "" and requested_node_id in graph["attribution"]:
        chain = []
        cur = requested_node_id
        attr = graph["attribution"]
        seen = set()
        while cur in attr and cur not in seen:
            seen.add(cur)
            chain.append({"node": cur, **attr[cur]})
            cur = attr[cur].get("parent")
            if cur is None or cur == "":
                break
        return {"node": requested_node_id, "inheritance_chain": chain, "graph_summary": {"nodes": graph["nodes"], "depth": graph["depth"]}}
    attribution = _replay_mapping_get(graph, "attribution", {})
    top_influences = sorted(
        _replay_mapping_items(attribution),
        key=lambda kv: -abs(_safe_replay_float(_replay_mapping_get(kv[1], "influence"))),
    )[:16]
    return {
        "graph_summary": {"nodes": graph["nodes"], "depth": graph["depth"]},
        "top_influences": top_influences,
    }


__all__ = ("ReplayBudget", "ReplayNode", "compress_replay_nodes", "garbage_collect_replay", "lineage_depth", "replay_influence_graph", "validate_replay_lineage", "why_suspicious_report")
