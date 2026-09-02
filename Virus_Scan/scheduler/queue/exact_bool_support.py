"""Canonical exact-bool materialization for scheduler queue helpers."""
from __future__ import annotations


def exact_bool(value: object) -> bool:
    """Return only exact bool values; reject bool-like or hostile objects."""
    return value if type(value) is bool else False


__all__ = ("exact_bool",)
