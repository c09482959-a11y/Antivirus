"""Canonical exact-text field-name helpers for scheduler queue modules."""
from __future__ import annotations


def queue_field_name(value: object) -> str:
    """Return a stable non-empty exact-string field name without caller hooks."""
    if type(value) is str and value:
        return str.__str__(value)
    return "field"


__all__ = ("queue_field_name",)
