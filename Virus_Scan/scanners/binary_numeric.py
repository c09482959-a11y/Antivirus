"""Scanner-owned numeric helpers for binary/entropy scoring."""
from __future__ import annotations

import math


def _scanner_numeric_field_name(field: object) -> str:
    if type(field) is str and field:
        return str.__str__(field)
    return "value"


def _scanner_numeric_field_suffix(field: object, suffix: str) -> str:
    return _scanner_numeric_field_name(field) + suffix


def _scanner_numeric_error(kind: str, field: object) -> TypeError:
    return TypeError("unsupported scanner numeric " + kind + ": " + _scanner_numeric_field_name(field))


def _exact_scanner_float(value: object, *, field: object) -> float:
    """Return exact primitive scanner numeric input without caller-owned hooks."""
    if type(value) is bool:
        raise _scanner_numeric_error("boolean", field)
    if type(value) is int or type(value) is float:
        return float(value)
    raise _scanner_numeric_error("object", field)


def safe_clamp(value: object, lo: float = 0.0, hi: float = 1.0, *, field: str = "value") -> float:
    """Clamp scanner scores without invoking caller-owned numeric hooks.

    The binary scanner score boundary accepts only exact primitive ``int`` and
    ``float`` values.  Numeric-like external objects are rejected before
    ``__float__``/``__int__`` can execute, so malformed scanner evidence cannot
    be converted into a clean low score by hookable best-effort coercion.
    """
    lower = _exact_scanner_float(lo, field="lo")
    upper = _exact_scanner_float(hi, field="hi")
    if lower > upper:
        lower, upper = upper, lower
    numeric = _exact_scanner_float(value, field=_scanner_numeric_field_name(field))
    if not math.isfinite(numeric):
        return lower
    return max(lower, min(upper, numeric))


def scanner_clamped_probability(value: object, *, field: str = "value") -> float:
    return safe_clamp(value, field=field)


def scanner_exact_float(value: object, *, field: str = "value") -> float:
    return _exact_scanner_float(value, field=field)


def scanner_clamped_ratio(numerator: object, denominator: object, *, field: str = "value", lo: float = 0.0, hi: float = 1.0) -> float:
    numerator_value = _exact_scanner_float(numerator, field=_scanner_numeric_field_name(field))
    denominator_value = _exact_scanner_float(denominator, field=_scanner_numeric_field_suffix(field, "_denominator"))
    if not math.isfinite(denominator_value) or denominator_value <= 0.0:
        denominator_value = 1.0
    return safe_clamp(numerator_value / denominator_value, lo, hi, field=field)


__all__ = ("safe_clamp", "scanner_clamped_probability", "scanner_clamped_ratio", "scanner_exact_float")
