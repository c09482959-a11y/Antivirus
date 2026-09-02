"""Replayable exact integer text parsing decisions for scheduler helpers."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExactIntTextDecision:
    """Typed decision for exact signed decimal text parsing."""

    accepted: bool
    value: int
    reason: str
    normalized_text: str


def exact_int_text_decision(
    value: str,
    *,
    empty_reason: str,
    sign_only_reason: str,
    digit_reason: str,
) -> ExactIntTextDecision:
    """Parse exact signed decimal text without hiding rejection as ``None``."""

    text = str.__str__(value).strip()
    if text == "":
        return ExactIntTextDecision(accepted=False, value=0, reason=empty_reason, normalized_text=text)
    sign = 1
    digits = text
    if text[0] in {"+", "-"}:
        if len(text) == 1:
            return ExactIntTextDecision(accepted=False, value=0, reason=sign_only_reason, normalized_text=text)
        sign = -1 if text[0] == "-" else 1
        digits = text[1:]
    if not digits.isdecimal():
        return ExactIntTextDecision(accepted=False, value=0, reason=digit_reason, normalized_text=text)
    return ExactIntTextDecision(accepted=True, value=sign * int(digits, 10), reason="", normalized_text=text)


__all__ = ("ExactIntTextDecision", "exact_int_text_decision")
