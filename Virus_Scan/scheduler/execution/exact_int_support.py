"""Canonical no-hook integer projection for scheduler execution boundaries."""
from __future__ import annotations

import math


def execution_exact_int(value: object, default_value: int, *, minimum: int = 0, reason: str) -> tuple[int, str]:
    """Return a replayable exact integer projection without caller hooks."""
    parsed: int | None
    if value is None:
        parsed = default_value
    elif type(value) is bool:
        return default_value, reason
    elif type(value) is int:
        parsed = value
    elif type(value) is float:
        if not math.isfinite(value) or not value.is_integer():
            return default_value, reason
        parsed = int(value)
    elif type(value) is str:
        text = str.__str__(value).strip()
        if text == "":
            return default_value, reason
        sign = 1
        digits = text
        if text[0] in {"+", "-"}:
            sign = -1 if text[0] == "-" else 1
            digits = text[1:]
        if not digits.isdecimal():
            return default_value, reason
        parsed = sign * int(digits, 10)
    else:
        return default_value, reason
    if parsed < minimum:
        return minimum, ""
    return parsed, ""


__all__ = ("execution_exact_int",)
