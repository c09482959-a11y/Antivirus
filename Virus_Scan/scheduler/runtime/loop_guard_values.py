"""No-hook scheduler loop guard value parsing."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_float,
    scheduler_int,
    scheduler_text,
    scheduler_value_snapshot,
)


def guard_reason(field_name: object, suffix: str) -> str:
    name = field_name if type(field_name) is str and field_name else "scheduler_loop_field"
    suffix_text = suffix if type(suffix) is str and suffix else "rejected"
    return name + "_" + suffix_text


def guard_issue(field_name: str, value: object, reason: str) -> Mapping[str, object]:
    return {
        "scheduler_loop_guard_input_rejected": True,
        "field_name": field_name,
        "reason": reason,
        "value": scheduler_value_snapshot(value, field_name=field_name),
    }


def guard_text(
    value: object, *, field_name: str, default_value: str
) -> tuple[str, tuple[Mapping[str, object], ...]]:
    text, reason = scheduler_text(
        value, replacement_text=default_value, unsupported_reason=guard_reason(field_name, "rejected")
    )
    if reason or text == "":
        issue = reason or guard_reason(field_name, "blank")
        return default_value, (guard_issue(field_name, value, issue),)
    return text, ()


def guard_int(
    value: object, *, field_name: str, default_value: int, minimum: int = 0
) -> tuple[int, tuple[Mapping[str, object], ...]]:
    parsed, reason = scheduler_int(
        value, default=default_value, reason=guard_reason(field_name, "rejected")
    )
    if reason:
        return default_value, (guard_issue(field_name, value, reason),)
    if parsed < minimum:
        return minimum, (
            guard_issue(field_name, value, guard_reason(field_name, "below_minimum")),
        )
    return parsed, ()


def guard_float(
    value: object, *, field_name: str, default_value: float, minimum: float = 0.0
) -> tuple[float, tuple[Mapping[str, object], ...]]:
    parsed, reason = scheduler_float(
        value, default=default_value, reason=guard_reason(field_name, "rejected")
    )
    if reason:
        return default_value, (guard_issue(field_name, value, reason),)
    if parsed < minimum:
        return minimum, (
            guard_issue(field_name, value, guard_reason(field_name, "below_minimum")),
        )
    return parsed, ()


__all__ = ("guard_float", "guard_int", "guard_issue", "guard_reason", "guard_text")
