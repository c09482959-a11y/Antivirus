"""No-hook scheduler context snapshot coercion helpers."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.internal.context_numeric_support import (
    indexed_context_field_name,
    parse_context_float,
    parse_context_int,
    safe_context_float_default,
    safe_context_int_default,
)


def _field_evidence(value: object, *, field_name: str, reason: str) -> dict[str, object]:
    evidence = unsupported_scheduler_value_evidence(value, field_name=field_name)
    if type(evidence) is dict:
        evidence = dict(evidence)
        evidence["reason"] = reason
        return evidence
    return {
        "unsupported_scheduler_value": True,
        "field": field_name,
        "reason": reason,
        "evidence": evidence,
    }


def context_text(value: object, *, field_name: str, default: str = "") -> tuple[str, tuple[dict[str, object], ...]]:
    """Return exact builtin text only; reject unknown objects before hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="scheduler_context_text_missing",
        unsupported_reason="unsupported_scheduler_context_text",
    )
    if reason == "":
        return text, ()
    if value is None:
        return default, ()
    return default, (_field_evidence(value, field_name=field_name, reason=reason),)


def context_int(value: object, *, field_name: str, default: int = 0, minimum: int | None = None) -> tuple[int, tuple[dict[str, object], ...]]:
    parsed, reason = parse_context_int(value, default=default, minimum=minimum)
    if reason and value is not None:
        return safe_context_int_default(default, minimum=minimum), (_field_evidence(value, field_name=field_name, reason=reason),)
    return parsed, ()


def context_float(value: object, *, field_name: str, default: float = 0.0, minimum: float | None = None) -> tuple[float, tuple[dict[str, object], ...]]:
    parsed, reason = parse_context_float(value, default=default, minimum=minimum)
    if reason and value is not None:
        return safe_context_float_default(default, minimum=minimum), (_field_evidence(value, field_name=field_name, reason=reason),)
    return parsed, ()


def context_bool(value: object, *, field_name: str, default: bool = False) -> tuple[bool, tuple[dict[str, object], ...]]:
    parsed, reason = scheduler_bool(
        value,
        default=default,
        reason="unsupported_scheduler_context_bool",
    )
    if reason and value is not None:
        return default, (_field_evidence(value, field_name=field_name, reason=reason),)
    return parsed, ()


def context_text_tuple(value: object, *, field_name: str) -> tuple[tuple[str, ...], tuple[dict[str, object], ...]]:
    if value is None:
        return (), ()
    if type(value) is not list and type(value) is not tuple:
        text, text_evidence = context_text(value, field_name=field_name, default="")
        if text_evidence:
            return (), text_evidence
        return (text,), ()
    out: list[str] = []
    evidence_items: list[dict[str, object]] = []
    for index, item in enumerate(value):
        text, item_evidence = context_text(item, field_name=indexed_context_field_name(field_name, index))
        if item_evidence:
            evidence_items.extend(item_evidence)
            continue
        out.append(text)
    return tuple(out), tuple(evidence_items)


def merge_context_evidence(*groups: object) -> tuple[object, ...]:
    merged: list[object] = []
    for group in groups:
        if not group:
            continue
        if type(group) is list:
            merged.extend(group)
        elif type(group) is tuple:
            merged.extend(group)
        else:
            merged.append(group)
    return immutable_tuple(tuple(merged))


__all__ = (
    "context_bool",
    "context_float",
    "context_int",
    "context_text",
    "context_text_tuple",
    "merge_context_evidence",
)
