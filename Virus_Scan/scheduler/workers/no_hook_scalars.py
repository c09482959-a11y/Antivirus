"""Shared no-hook scalar coercion for scheduler worker boundaries."""
from __future__ import annotations

from dataclasses import dataclass
import math

from Virus_Scan.scheduler.internal.exact_integer_bounds import clamp_exact_int
from Virus_Scan.scheduler.internal.exact_integer_text import parse_exact_integer_text



@dataclass(frozen=True, slots=True)
class WorkerIntegerTextDecision:
    value: int
    reason: str
    replacement_used: bool


def _int_text_decision(value: str) -> WorkerIntegerTextDecision:
    parsed = parse_exact_integer_text(
        value,
        empty_reason="worker_int_text_missing",
        sign_without_digits_reason="worker_int_sign_without_digits",
        not_decimal_reason="worker_int_text_rejected",
    )
    return WorkerIntegerTextDecision(parsed.value, parsed.reason, parsed.reason != "")


def worker_int(
    value: object,
    *,
    replacement: int = 0,
    minimum: int | None = None,
    maximum: int | None = None,
    reason: str = "worker_integer_rejected",
) -> tuple[int, str]:
    replacement_value = clamp_exact_int(replacement if type(replacement) is int and type(replacement) is not bool else 0, minimum=minimum, maximum=maximum)
    if value is None:
        return replacement_value, ""
    parsed: int
    if type(value) is bool:
        return replacement_value, reason
    if type(value) is int:
        parsed = value
    elif type(value) is float:
        if not math.isfinite(value) or not value.is_integer():
            return replacement_value, reason
        parsed = int(value)
    elif type(value) is str:
        decision = _int_text_decision(value)
        if decision.reason:
            return replacement_value, reason
        parsed = decision.value
    elif type(value) is bytes:
        decision = _int_text_decision(bytes(value).decode("utf-8", "replace"))
        if decision.reason:
            return replacement_value, reason
        parsed = decision.value
    elif type(value) is bytearray:
        decision = _int_text_decision(bytes(value).decode("utf-8", "replace"))
        if decision.reason:
            return replacement_value, reason
        parsed = decision.value
    else:
        return replacement_value, reason
    return clamp_exact_int(parsed, minimum=minimum, maximum=maximum), ""



def _float_replacement(value: object) -> float:
    if type(value) is int and type(value) is not bool:
        metric = value + 0.0
    elif type(value) is float:
        metric = value
    else:
        return 0.0
    return metric if math.isfinite(metric) else 0.0


def worker_float(
    value: object,
    *,
    replacement: float = 0.0,
    minimum: float | None = None,
    reason: str = "worker_float_rejected",
) -> tuple[float, str]:
    replacement_value = _float_replacement(replacement)
    if value is None:
        return replacement_value, ""
    if type(value) is bool:
        return replacement_value, reason
    if type(value) is int:
        metric = value + 0.0
    elif type(value) is float:
        metric = value
    elif type(value) is str:
        try:
            metric = float(str.__str__(value).strip())
        except (TypeError, ValueError, OverflowError):
            return replacement_value, reason
    elif type(value) is bytes:
        try:
            metric = float(bytes(value).decode("utf-8", "replace").strip())
        except (TypeError, ValueError, OverflowError):
            return replacement_value, reason
    elif type(value) is bytearray:
        try:
            metric = float(bytes(value).decode("utf-8", "replace").strip())
        except (TypeError, ValueError, OverflowError):
            return replacement_value, reason
    else:
        return replacement_value, reason
    if not math.isfinite(metric):
        return replacement_value, reason
    if minimum is not None and metric < minimum:
        metric = minimum
    return metric, ""


def worker_optional_float(value: object, *, minimum: float | None = None, reason: str = "worker_float_rejected") -> tuple[float | None, str]:
    if value is None:
        return None, ""
    parsed, issue = worker_float(value, replacement=0.0, minimum=minimum, reason=reason)
    if issue:
        return None, issue
    return parsed, ""


def worker_bool(value: object, *, replacement: bool = False, reason: str = "worker_bool_rejected") -> tuple[bool, str]:
    safe_replacement = replacement if type(replacement) is bool else False
    if type(value) is bool:
        return value, ""
    if type(value) is int:
        return value != 0, ""
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text in {"1", "true", "yes", "on", "enabled"}:
            return True, ""
        if text in {"0", "false", "no", "off", "disabled", ""}:
            return False, ""
    return safe_replacement, reason


__all__ = ("WorkerIntegerTextDecision", "worker_bool", "worker_float", "worker_int", "worker_optional_float")
