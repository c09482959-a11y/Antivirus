"""Shared exact-integer bound helpers for scheduler contracts."""
from __future__ import annotations


def clamp_exact_int(
    value: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Clamp an already accepted exact integer to optional inclusive bounds."""
    bounded = value
    if minimum is not None and bounded < minimum:
        bounded = minimum
    if maximum is not None and bounded > maximum:
        bounded = maximum
    return bounded
