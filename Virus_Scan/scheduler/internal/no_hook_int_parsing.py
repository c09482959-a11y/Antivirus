"""No-hook integer parsing support for scheduler diagnostics."""
from __future__ import annotations

import math
from dataclasses import dataclass

from Virus_Scan.scheduler.internal.exact_int_text_decision import exact_int_text_decision


@dataclass(frozen=True, slots=True)
class SchedulerIntParseResult:
    """Parsed scheduler integer value without invoking caller-owned hooks."""

    accepted: bool
    value: int
    reason: str



def _parse_scheduler_int_text(text: str, *, reason: str) -> SchedulerIntParseResult:
    decision = exact_int_text_decision(
        text,
        empty_reason="scheduler_integer_text_empty",
        sign_only_reason="scheduler_integer_text_sign_only",
        digit_reason="scheduler_integer_text_digits_rejected",
    )
    accepted = bool(decision.accepted)
    value = decision.value if accepted else 0
    rejection_reason = "" if accepted else reason
    return SchedulerIntParseResult(accepted=accepted, value=value, reason=rejection_reason)


def parse_scheduler_int_value(value: object, *, reason: str) -> SchedulerIntParseResult:
    """Parse exact scheduler integer inputs without falling through hooks."""

    if value is None:
        return SchedulerIntParseResult(accepted=False, value=0, reason="")
    if type(value) is bool:
        return SchedulerIntParseResult(accepted=False, value=0, reason=reason)
    if type(value) is int:
        return SchedulerIntParseResult(accepted=True, value=value, reason="")
    if type(value) is float:
        accepted = math.isfinite(value) and value.is_integer()
        parsed_value = int(value) if accepted else 0
        rejection_reason = "" if accepted else reason
        return SchedulerIntParseResult(accepted=accepted, value=parsed_value, reason=rejection_reason)
    if type(value) is str:
        return _parse_scheduler_int_text(value, reason=reason)
    if type(value) in {bytes, bytearray}:
        return _parse_scheduler_int_text(bytes(value).decode("utf-8", "replace"), reason=reason)
    return SchedulerIntParseResult(accepted=False, value=0, reason=reason)


__all__ = ("SchedulerIntParseResult", "parse_scheduler_int_value")
