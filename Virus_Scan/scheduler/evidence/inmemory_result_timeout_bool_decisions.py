"""Typed no-hook boolean decisions for in-memory timeout evidence."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items


_TRUE_TEXT = ("1", "true", "yes", "failed", "failure", "fatal", "error", "timeout")
_FALSE_TEXT = ("0", "false", "no", "ok", "clean", "success", "passed")


@dataclass(frozen=True)
class TimeoutBooleanDecision:
    field: str
    value: bool
    reason: str
    rejected: bool = False


@dataclass(frozen=True)
class TimeoutTagsDecision:
    value: tuple[object, ...]
    reason: str
    rejected: bool = False


def timeout_bool_decision(value: object, *, field: str) -> TimeoutBooleanDecision:
    if type(value) is bool:
        return TimeoutBooleanDecision(field=field, value=value, reason="scheduler_boolean_exact_bool")
    if value is None:
        return TimeoutBooleanDecision(field=field, value=False, reason="scheduler_boolean_missing")
    if type(value) is int:
        return TimeoutBooleanDecision(field=field, value=value != 0, reason="scheduler_boolean_exact_integer")
    if type(value) is str:
        text = str.__str__(value).lower()
        if text in _TRUE_TEXT:
            return TimeoutBooleanDecision(field=field, value=True, reason="scheduler_boolean_text_true")
        if text in _FALSE_TEXT:
            return TimeoutBooleanDecision(field=field, value=False, reason="scheduler_boolean_text_false")
    return TimeoutBooleanDecision(
        field=field,
        value=False,
        reason="unsafe_scheduler_boolean_rejected",
        rejected=True,
    )


def timeout_tags_decision(value: object) -> TimeoutTagsDecision:
    if value is None:
        return TimeoutTagsDecision(value=(), reason="scheduler_tags_missing")
    items = no_hook_sequence_items(value)
    if not items and type(value) not in (list, tuple, set, frozenset):
        return TimeoutTagsDecision(
            value=items,
            reason="unsafe_scheduler_tag_sequence_rejected",
            rejected=True,
        )
    return TimeoutTagsDecision(value=items, reason="scheduler_tags_sequence_materialized")


__all__ = (
    "TimeoutBooleanDecision",
    "TimeoutTagsDecision",
    "timeout_bool_decision",
    "timeout_tags_decision",
)
