"""Canonical hostile-safe exact numeric boundary contracts."""
from __future__ import annotations


def exact_bounded_nonnegative_int(
    value: object,
    reason: str,
    *,
    maximum: int,
) -> int:
    """Return an exact built-in non-negative integer within ``maximum``."""
    if type(maximum) is not int or type(maximum) is bool or maximum < 0:
        raise TypeError("numeric_boundary_maximum_invalid")
    if type(value) is not int or type(value) is bool:
        raise TypeError(reason)
    if value < 0 or value > maximum:
        raise ValueError(reason)
    return value


def exact_bool(value: object, reason: str) -> bool:
    """Return an exact built-in boolean or fail with the supplied reason."""
    if type(value) is not bool:
        raise TypeError(reason)
    return value


def exact_optional_rate(numerator: object, denominator: object) -> float | None:
    """Return one canonical twelve-place rate or ``None`` for no support."""
    if type(numerator) is not int or type(numerator) is bool or numerator < 0:
        raise TypeError("numeric_rate_numerator_invalid")
    if type(denominator) is not int or type(denominator) is bool or denominator < 0:
        raise TypeError("numeric_rate_denominator_invalid")
    if denominator == 0:
        return None
    if numerator > denominator:
        raise ValueError("numeric_rate_support_invalid")
    return round(numerator / denominator, 12)


__all__ = ("exact_bool", "exact_bounded_nonnegative_int", "exact_optional_rate")
