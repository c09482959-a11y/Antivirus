"""Scanner-owned entropy math helpers for binary/entropy analysis."""
from __future__ import annotations

from collections import Counter
import math
from typing import Iterable

from Virus_Scan.scanners.binary_numeric import scanner_exact_float


def _scanner_entropy_bytes(buf: bytes | bytearray | memoryview | None) -> bytes:
    if buf is None:
        return b""
    if type(buf) is bytes:
        return bytes(buf)
    if type(buf) is bytearray:
        return bytes(buf)
    if type(buf) is memoryview:
        return buf.tobytes()
    exception_message = "unsupported scanner entropy bytes: buf"
    raise TypeError(exception_message)


def _scanner_entropy_counter_values(data: bytes) -> tuple[int, ...]:
    counts = Counter(data)
    return tuple(dict.values(counts))


def _scanner_entropy_count_items(counts: Iterable[int] | None) -> tuple[object, ...]:
    if counts is None:
        return ()
    if type(counts) in (tuple, list, set, frozenset):
        return tuple(counts)
    exception_message = "unsupported scanner entropy counts: counts"
    raise TypeError(exception_message)


def _scanner_entropy_float_or_zero(value: object, *, field: str) -> float:
    if value is None:
        return 0.0
    return scanner_exact_float(value, field=field)


def shannon_entropy_bytes(buf: bytes | bytearray | memoryview | None) -> float:
    """Return non-negative Shannon entropy for a bytes-like sample."""
    data = _scanner_entropy_bytes(buf)
    if len(data) == 0:
        return 0.0
    total = float(len(data))
    entropy = 0.0
    for count in _scanner_entropy_counter_values(data):
        probability = float(count) / total
        entropy -= probability * math.log2(probability + 1e-12)
    return max(0.0, float(entropy))


def entropy_from_counts(counts: Iterable[int] | None, total: float) -> float:
    """Return non-negative Shannon entropy for precomputed counts."""
    total_f = _scanner_entropy_float_or_zero(total, field="total")
    if total_f <= 0:
        return 0.0
    entropy = 0.0
    for count in _scanner_entropy_count_items(counts):
        count_f = _scanner_entropy_float_or_zero(count, field="count")
        if count_f <= 0:
            continue
        probability = count_f / total_f
        entropy -= probability * math.log2(probability + 1e-12)
    return max(0.0, float(entropy))


__all__ = ("entropy_from_counts", "shannon_entropy_bytes")
