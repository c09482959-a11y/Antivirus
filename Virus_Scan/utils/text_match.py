"""Canonical text matching helpers shared by scanners and path policy.

This module is intentionally dependency-light so low-level runtime/path modules
can use substring matching without importing scanner implementations.
"""
from __future__ import annotations



from Virus_Scan.utils.text_validation import text_boundary_value


def _text_match_value(value: object) -> str:
    text = text_boundary_value(value, unsupported="")
    if type(text) is str:
        return str.__str__(text)
    return ""


def _text_match_needles(needles: object) -> tuple[object, ...]:
    if needles is None:
        values: tuple[object, ...] = ()
    elif type(needles) is str:
        values = (needles,)
    elif type(needles) is tuple:
        values = needles
    elif type(needles) is list:
        values = tuple(needles)
    elif type(needles) in (set, frozenset):
        values = tuple(
            sorted(needles, key=lambda item: _text_match_value(item).lower())
        )
    else:
        values = ()
    return values


def has_any_text(text: object, needles: object) -> bool:
    haystack = _text_match_value(text).lower()
    if haystack == "":
        return False
    for needle in _text_match_needles(needles):
        needle_text = _text_match_value(needle).lower()
        if needle_text and needle_text in haystack:
            return True
    return False

__all__ = ("has_any_text",)
