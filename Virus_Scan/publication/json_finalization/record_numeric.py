"""Exact numeric helpers for compact final JSON record fields."""
from __future__ import annotations
from typing import TYPE_CHECKING

import math

if TYPE_CHECKING:
    from collections.abc import Callable

_NO_NUMERIC_VALUE = None


def _float_from_text(text: str) -> float | None:
    try:
        numeric = float(text)
    except (TypeError, ValueError):
        return _NO_NUMERIC_VALUE
    if not math.isfinite(numeric):
        return _NO_NUMERIC_VALUE
    return numeric


def exact_int_value(value: object, text_value: Callable[[object], str]) -> int | None:
    if type(value) is bool:
        return _NO_NUMERIC_VALUE
    if type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value) or not value.is_integer():
            return _NO_NUMERIC_VALUE
        return int(value)
    text = text_value(value)
    if text == "":
        return _NO_NUMERIC_VALUE
    numeric = _float_from_text(text)
    if numeric is None or not numeric.is_integer():
        return _NO_NUMERIC_VALUE
    return int(numeric)


def exact_nonnegative_float(value: object, text_value: Callable[[object], str]) -> float | None:
    if type(value) is bool:
        return _NO_NUMERIC_VALUE
    if type(value) is int:
        return float(value) if value >= 0 else _NO_NUMERIC_VALUE
    if type(value) is float:
        if not math.isfinite(value) or value < 0:
            return _NO_NUMERIC_VALUE
        return value
    text = text_value(value)
    if text == "":
        return _NO_NUMERIC_VALUE
    numeric = _float_from_text(text)
    if numeric is None or numeric < 0:
        return _NO_NUMERIC_VALUE
    return numeric
