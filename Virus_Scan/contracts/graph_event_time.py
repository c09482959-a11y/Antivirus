"""Shared graph event-time coercion contract."""

from __future__ import annotations

import math

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS


def _graph_event_time_text(value: object) -> str | None:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_graph_event_time",
        unsupported_reason="unsupported_graph_event_time",
    )
    if reason:
        return None
    return str.strip(text)


def _graph_event_time_candidate(value: object) -> float | None:
    if type(value) is bool:
        return None
    if type(value) is int:
        return float(value)
    if type(value) is float:
        return value
    try:
        text = _graph_event_time_text(value)
        return None if text is None else float(text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return None


def coerce_graph_event_time(value: object) -> object:
    numeric = _graph_event_time_candidate(value)
    if numeric is None:
        return None, "non_numeric_event_time"
    if not math.isfinite(numeric):
        return None, "non_finite_event_time"
    return numeric, ""


def graph_event_time_failure_reason(reasons: object) -> object:
    reason_set = set()
    for reason in no_hook_sequence_items(reasons):
        text, text_reason = no_hook_text(
            reason,
            missing_reason="missing_graph_event_time_reason",
            unsupported_reason="unsupported_graph_event_time_reason",
        )
        if text_reason == "":
            reason_set.add(str.__str__(text))
    reason_set.discard("")
    if "non_finite_event_time" in reason_set:
        return "non_finite_event_time"
    if "non_numeric_event_time" in reason_set:
        return "non_numeric_event_time"
    return ""


__all__ = (
    "coerce_graph_event_time",
    "graph_event_time_failure_reason",
)
