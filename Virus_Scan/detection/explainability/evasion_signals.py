"""Detection-owned evasion signal explanation helpers."""
from __future__ import annotations

import math
from collections import Counter

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)

PLR2004N20 = 20
PLR2004N2_5 = 2.5
PLR2004N3 = 3

_EDGE_KEYS = frozenset(("edges", "neighbors", "links"))


def _safe_tag_values(tags: object) -> tuple[str, ...]:
    values: list[str] = []
    for tag in no_hook_sequence_items(tags):
        text, reason = no_hook_text(
            tag,
            missing_reason="missing_evasion_tag",
            unsupported_reason="unsupported_evasion_tag",
        )
        if reason:
            continue
        normalized = str.strip(text).lower()
        if normalized:
            values.append(normalized)
    return tuple(values)


def _tag_entropy_values(values: tuple[str, ...]) -> float:
    if not values:
        return 0.0
    total = len(values) + 0.0
    counts = Counter(values)
    return -sum((count / total) * math.log2(count / total) for count in dict.values(counts) if count)


def _tag_entropy(tags: object) -> float:
    return _tag_entropy_values(_safe_tag_values(tags))


def _owned_edge_value_has_content(value: object) -> bool:
    if value is None:
        return False
    if type(value) is bool:
        return value
    if type(value) is int:
        return value != 0
    if type(value) is float:
        return math.isfinite(value) and value != 0.0
    if type(value) is str:
        return str.strip(value) != ""
    if type(value) in (bytes, bytearray):
        return len(value) > 0
    mapping_items = no_hook_mapping_items(value)
    if mapping_items is not None:
        return len(mapping_items) > 0
    if type(value) in (tuple, list, set, frozenset):
        return len(value) > 0
    return False


def _node_edge_status(node: object) -> tuple[str, bool]:
    if node is None:
        return "not_provided", False
    if type(node) is str:
        return "empty", False
    items = no_hook_mapping_items(node)
    if items is None:
        return "unsupported", False
    found = False
    for key, value in items:
        key_text, reason = no_hook_text(
            key,
            missing_reason="missing_evasion_edge_key",
            unsupported_reason="unsupported_evasion_edge_key",
        )
        if reason or key_text not in _EDGE_KEYS:
            continue
        found = True
        if _owned_edge_value_has_content(value):
            return "present", True
    return ("empty", False) if found else ("empty", False)


def _node_has_obvious_edges(node: object) -> bool:
    status, has_edges = _node_edge_status(node)
    return status == "present" and has_edges


def detect_evasion_signals(tags: object, node: object = None) -> float:
    signals = 0.0
    tag_values = _safe_tag_values(tags)
    if len(tag_values) > PLR2004N20:
        signals += 0.3
    if _tag_entropy_values(tag_values) > PLR2004N2_5:
        signals += 0.5
    node_status, has_edges = _node_edge_status(node)
    if node_status == "empty" and not has_edges:
        signals += 0.4
    lowered = frozenset(tag_values)
    if len(lowered) < PLR2004N3 and lowered & {"process_exec", "cmd_exec"}:
        signals += 0.3
    return min(1.0, signals)


__all__ = ("detect_evasion_signals",)
