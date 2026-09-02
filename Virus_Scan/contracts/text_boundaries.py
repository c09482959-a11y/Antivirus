"""Canonical hostile-safe bounded text materialization."""
from __future__ import annotations


def exact_bounded_text(
    value: object,
    reason: str,
    *,
    maximum: int = 512,
    allow_blank: bool = False,
) -> str:
    """Return an exact built-in string within explicit bounds."""
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value)
    if len(text) > maximum or (not allow_blank and text == ""):
        raise ValueError(reason)
    return text


__all__ = ("exact_bounded_text",)
