"""No-hook numeric parsing support for scheduler context snapshots."""
from __future__ import annotations

from dataclasses import dataclass
import math

from Virus_Scan.scheduler.internal.exact_integer_bounds import clamp_exact_int
from Virus_Scan.scheduler.internal.exact_integer_text import parse_exact_integer_text



@dataclass(frozen=True, slots=True)
class SchedulerContextIntDecision:
    value: int
    reason: str
    replacement_used: bool


def _exact_context_int_text_decision(value: str) -> SchedulerContextIntDecision:
    parsed = parse_exact_integer_text(
        value,
        empty_reason="scheduler_context_int_text_missing",
        sign_without_digits_reason="scheduler_context_int_sign_without_digits",
        not_decimal_reason="scheduler_context_int_text_rejected",
    )
    return SchedulerContextIntDecision(parsed.value, parsed.reason, parsed.reason != "")


def safe_context_int_default(value: object, *, minimum: int | None = None) -> int:
    if type(value) is int and type(value) is not bool:
        return clamp_exact_int(value, minimum=minimum)
    return clamp_exact_int(0, minimum=minimum)


def parse_context_int(value: object, *, default: int, minimum: int | None) -> tuple[int, str]:
    safe_default = safe_context_int_default(default, minimum=minimum)
    if value is None:
        return safe_default, ""
    parsed: int
    if type(value) is bool:
        return safe_default, "unsupported_scheduler_context_int"
    if type(value) is int:
        parsed = value
    elif type(value) is float:
        if not math.isfinite(value) or not value.is_integer():
            return safe_default, "unsupported_scheduler_context_int"
        parsed = int(value)
    elif type(value) is str:
        decision = _exact_context_int_text_decision(value)
        if decision.reason:
            return safe_default, "unsupported_scheduler_context_int"
        parsed = decision.value
    elif type(value) is bytes:
        decision = _exact_context_int_text_decision(bytes(value).decode("utf-8", "replace"))
        if decision.reason:
            return safe_default, "unsupported_scheduler_context_int"
        parsed = decision.value
    elif type(value) is bytearray:
        decision = _exact_context_int_text_decision(bytes(value).decode("utf-8", "replace"))
        if decision.reason:
            return safe_default, "unsupported_scheduler_context_int"
        parsed = decision.value
    else:
        return safe_default, "unsupported_scheduler_context_int"
    return clamp_exact_int(parsed, minimum=minimum), ""


def safe_context_float_default(value: object, *, minimum: float | None = None) -> float:
    if type(value) is bool:
        parsed = 0.0
    elif type(value) is int:
        parsed = value + 0.0
    elif type(value) is float and math.isfinite(value):
        parsed = value
    else:
        parsed = 0.0
    if minimum is not None and parsed < minimum:
        return minimum
    return parsed


def parse_context_float(value: object, *, default: float, minimum: float | None) -> tuple[float, str]:
    safe_default = safe_context_float_default(default, minimum=minimum)
    if value is None:
        return safe_default, ""
    if type(value) is bool:
        return safe_default, "unsupported_scheduler_context_float"
    if type(value) is int:
        metric = value + 0.0
    elif type(value) is float:
        metric = value
    elif type(value) is str:
        try:
            metric = float(str.__str__(value).strip())
        except (TypeError, ValueError, OverflowError):
            return safe_default, "unsupported_scheduler_context_float"
    elif type(value) is bytes:
        try:
            metric = float(bytes(value).decode("utf-8", "replace").strip())
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return safe_default, "unsupported_scheduler_context_float"
    elif type(value) is bytearray:
        try:
            metric = float(bytes(value).decode("utf-8", "replace").strip())
        except (TypeError, ValueError, OverflowError, UnicodeDecodeError):
            return safe_default, "unsupported_scheduler_context_float"
    else:
        return safe_default, "unsupported_scheduler_context_float"
    if not math.isfinite(metric):
        return safe_default, "non_finite_scheduler_context_float"
    if minimum is not None and metric < minimum:
        return minimum, ""
    return metric, ""


def indexed_context_field_name(field_name: str, index: int) -> str:
    base = str.__str__(field_name) if type(field_name) is str else "scheduler_context"
    return base + "_" + int.__str__(index)


__all__ = (
    "SchedulerContextIntDecision",
    "indexed_context_field_name",
    "parse_context_float",
    "parse_context_int",
    "safe_context_float_default",
    "safe_context_int_default",
)
