"""Scanner-owned text/byte signal helpers for binary behavior predicates."""
from __future__ import annotations

import re

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def binary_ascii_visibility_ratio(buf: bytes) -> float:
    """Return visible-ASCII ratio for binary samples without hiding helper failures."""
    if not buf:
        return 0.0
    visible = sum(1 for byte in buf if byte in (9, 10, 13) or 32 <= byte <= 126)
    return visible / float(len(buf))


def _binary_signal_text(value: object, *, unsupported_reason: str) -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_binary_signal_text",
        unsupported_reason=unsupported_reason,
    )
    if reason:
        return "", reason
    return text, ""


def _binary_signal_needles(needles: object) -> tuple[str, ...]:
    if needles is None:
        return ()
    if type(needles) in (str, bytes, bytearray, bool, int, float):
        text, reason = _binary_signal_text(
            needles,
            unsupported_reason="unsafe_binary_signal_needle_rejected",
        )
        normalized = str.strip(text)
        return (normalized,) if not reason and normalized else ()
    if type(needles) not in (tuple, list, set, frozenset):
        return ()
    out: list[str] = []
    for needle in tuple(needles):
        text, reason = _binary_signal_text(
            needle,
            unsupported_reason="unsafe_binary_signal_needle_rejected",
        )
        normalized = str.strip(text)
        if not reason and normalized:
            out.append(normalized)
    return tuple(out)


def binary_regex_match(pattern: str, text: str, flags: int = 0) -> bool:
    """Conservative regex predicate used by binary behavior heuristics."""
    pattern_text, pattern_reason = _binary_signal_text(
        pattern,
        unsupported_reason="unsafe_binary_regex_pattern_rejected",
    )
    haystack, text_reason = _binary_signal_text(
        text,
        unsupported_reason="unsafe_binary_regex_text_rejected",
    )
    if pattern_reason:
        raise TypeError(pattern_reason)
    if text_reason:
        raise TypeError(text_reason)
    if not pattern_text:
        raise TypeError("empty_binary_regex_pattern")
    return re.search(pattern_text, haystack, flags | re.IGNORECASE) is not None


def binary_text_has_any(text: object, needles: object) -> bool:
    """Return True when a non-empty scanner-owned binary text marker appears."""
    haystack, reason = _binary_signal_text(
        text,
        unsupported_reason="unsafe_binary_signal_text_rejected",
    )
    if reason:
        return False
    normalized_needles = _binary_signal_needles(needles)
    return any(needle in haystack for needle in normalized_needles)


__all__ = ("binary_ascii_visibility_ratio", "binary_regex_match", "binary_text_has_any")
