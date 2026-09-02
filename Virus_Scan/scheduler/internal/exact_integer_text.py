"""Canonical no-hook exact integer text parsing for scheduler boundaries."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExactIntegerTextParse:
    """Replayable result for exact decimal integer text parsing."""

    value: int
    reason: str


def parse_exact_integer_text(
    value: str,
    *,
    empty_reason: str,
    sign_without_digits_reason: str,
    not_decimal_reason: str,
) -> ExactIntegerTextParse:
    """Parse exact signed decimal text without invoking caller-owned hooks."""
    text = str.__str__(value).strip()
    if text == "":
        return ExactIntegerTextParse(0, empty_reason)
    sign = 1
    digits = text
    if text[0] in {"+", "-"}:
        if len(text) == 1:
            return ExactIntegerTextParse(0, sign_without_digits_reason)
        sign = -1 if text[0] == "-" else 1
        digits = text[1:]
    if not digits.isdecimal():
        return ExactIntegerTextParse(0, not_decimal_reason)
    return ExactIntegerTextParse(sign * int(digits, 10), "")


def scheduler_int_text(value: int) -> str:
    """Project a scheduler-owned integer as text without dynamic formatting hooks."""
    return int.__str__(value)


__all__ = ("ExactIntegerTextParse", "parse_exact_integer_text", "scheduler_int_text")
