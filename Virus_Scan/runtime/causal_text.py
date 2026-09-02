"""Detached text projection for causal replay/runtime snapshot evidence.

This module is intentionally runtime-local.  It prevents replay-facing causal
records from invoking caller-owned ``__str__``, ``__fspath__``, or truthiness
methods while still preserving ordinary owned string, bytes, and scalar inputs.
"""
from __future__ import annotations

import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

_UNAVAILABLE_PREFIX = "causal_text_unavailable"
_EMPTY_TEXT = "causal_text_empty"


def _causal_owned_text(*parts: str) -> str:
    return "".join(parts)


def _type_name(value: object) -> str:
    return no_hook_type_name(value)


def causal_text(value: object, *, default: str = "", empty: str | None = None) -> str:
    """Project a value to deterministic replay text without arbitrary str()."""
    if value is None:
        return default
    if type(value) is str:
        text = value
    elif isinstance(value, str):
        text = "".join((str.__str__(value),))
    elif type(value) is bytes:
        text = bytes.decode(value, "utf-8", "replace")
    elif type(value) is bytearray:
        text = bytearray.decode(value, "utf-8", "replace")
    elif type(value) is bool:
        text = "true" if value else "false"
    elif type(value) is int:
        text = str.__str__(int.__str__(value))
    elif type(value) is float:
        text = (
            float.__repr__(value)
            if math.isfinite(value)
            else _UNAVAILABLE_PREFIX + ":nonfinite_float"
        )
    else:
        return _causal_owned_text(_UNAVAILABLE_PREFIX, ":", _type_name(value))
    if text == "" and empty is not None:
        return empty
    return text


def causal_text_default(value: object, default: str) -> str:
    text = causal_text(value, default=default, empty=default)
    return text if text != "" else default


def causal_sort_key(value: object) -> tuple[str, str]:
    text = causal_text(value, empty=_EMPTY_TEXT)
    return (text, _type_name(value))


def causal_scalar_token(value: object) -> str:
    if type(value) is str or isinstance(value, str):
        return causal_text(value, empty=_EMPTY_TEXT)
    if isinstance(value, (bytes, bytearray, bool, int, float)) or value is None:
        return causal_text(value, default="null", empty=_EMPTY_TEXT)
    return _causal_owned_text("<", _type_name(value), ">")


__all__ = ("causal_scalar_token", "causal_sort_key", "causal_text", "causal_text_default")
