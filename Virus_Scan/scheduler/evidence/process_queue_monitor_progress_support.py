"""Strict no-hook scalar/text support for process-queue monitor progress."""
from __future__ import annotations

import math
from dataclasses import dataclass

from Virus_Scan.scheduler.internal.exact_integer_text import parse_exact_integer_text, scheduler_int_text



@dataclass(frozen=True)
class MonitorProgressIntDecision:
    """Replayable no-hook integer parsing decision for monitor progress."""

    value: int
    accepted: bool
    reason: str



def _exact_int_text_decision(value: str) -> MonitorProgressIntDecision:
    parsed = parse_exact_integer_text(
        value,
        empty_reason="monitor_progress_integer_text_empty",
        sign_without_digits_reason="monitor_progress_integer_sign_without_digits",
        not_decimal_reason="monitor_progress_integer_text_not_decimal",
    )
    return MonitorProgressIntDecision(value=parsed.value, accepted=parsed.reason == "", reason=parsed.reason)


def _clamp_zero(value: int) -> int:
    return max(value, 0)


def monitor_progress_int_decision(value: object, reason: str) -> MonitorProgressIntDecision:
    """Return a replayable monitor-progress integer parse decision."""
    parsed: int
    if type(value) is bool or value is None:
        return MonitorProgressIntDecision(value=0, accepted=reason == "", reason=reason)
    if type(value) is int:
        parsed = value
    elif type(value) is float:
        if not math.isfinite(value) or not value.is_integer():
            return MonitorProgressIntDecision(value=0, accepted=reason == "", reason=reason)
        parsed = int(value)
    elif type(value) is str:
        decision = _exact_int_text_decision(value)
        if not decision.accepted:
            return MonitorProgressIntDecision(value=0, accepted=reason == "", reason=reason)
        parsed = decision.value
    elif type(value) is bytes:
        decision = _exact_int_text_decision(bytes(value).decode("utf-8", "replace"))
        if not decision.accepted:
            return MonitorProgressIntDecision(value=0, accepted=reason == "", reason=reason)
        parsed = decision.value
    elif type(value) is bytearray:
        decision = _exact_int_text_decision(bytes(value).decode("utf-8", "replace"))
        if not decision.accepted:
            return MonitorProgressIntDecision(value=0, accepted=reason == "", reason=reason)
        parsed = decision.value
    else:
        return MonitorProgressIntDecision(value=0, accepted=reason == "", reason=reason)
    return MonitorProgressIntDecision(value=_clamp_zero(parsed), accepted=True, reason="")


def monitor_progress_int(value: object, reason: str) -> int:
    decision = monitor_progress_int_decision(value, reason)
    if not decision.accepted:
        raise ValueError(decision.reason)
    return decision.value


def monitor_progress_float(value: object, reason: str, *, maximum: float | None = None) -> float:
    if type(value) is bool or value is None:
        raise ValueError(reason)
    if type(value) is int:
        metric = value + 0.0
    elif type(value) is float:
        metric = value
    elif type(value) is str:
        try:
            metric = float(str.__str__(value).strip())
        except (TypeError, ValueError):
            raise ValueError(reason) from None
    elif type(value) is bytes:
        try:
            metric = float(bytes(value).decode("utf-8", "replace").strip())
        except (TypeError, ValueError):
            raise ValueError(reason) from None
    elif type(value) is bytearray:
        try:
            metric = float(bytes(value).decode("utf-8", "replace").strip())
        except (TypeError, ValueError):
            raise ValueError(reason) from None
    else:
        raise ValueError(reason)
    if not math.isfinite(metric):
        raise ValueError(reason)
    metric = max(metric, 0.0)
    if maximum is not None and metric > maximum:
        metric = maximum
    return metric


progress_int_text = scheduler_int_text


def progress_float_percent(value: float) -> str:
    return float.__format__(value, ".1f") + "%"


def progress_cpu_text(value: float | None) -> str:
    if value is None:
        return "n/a"
    return progress_float_percent(value)


__all__ = (
    "MonitorProgressIntDecision",
    "monitor_progress_float",
    "monitor_progress_int",
    "monitor_progress_int_decision",
    "progress_cpu_text",
    "progress_int_text",
)
