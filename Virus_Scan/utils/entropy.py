"""Direct-import-safe entropy helpers shared by scanner/runtime modules."""
from __future__ import annotations

from collections import Counter
import math
from typing import Iterable

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)


def _entropy_bytes(buf: bytes | bytearray | memoryview | None) -> bytes:
    if buf is None:
        return b""
    if type(buf) is bytes:
        return bytes(buf)
    if type(buf) is bytearray:
        return bytes(buf)
    if type(buf) is memoryview:
        try:
            return bytes(buf)
        except (ValueError, TypeError):
            return b""
    return b""


def shannon_entropy_bytes(buf: bytes | bytearray | memoryview | None) -> float:
    """Return Shannon entropy for a bytes-like buffer without scanner state."""
    data = _entropy_bytes(buf)
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data) + 0.0
    ent = 0.0
    for _value, count in no_hook_mapping_items(counts, allow_dict_subclass=True) or ():
        p = count / total
        ent -= p * math.log2(p + 1e-12)
    return ent


def entropy_from_counts(counts: Iterable[int] | None, total: float) -> float:
    """Entropy for precomputed counts used by image/stego checks."""
    total_f, total_reason = no_hook_finite_float(total, default=0.0, reason="invalid_entropy_total")
    if total_reason or total_f <= 0:
        return 0.0
    ent = 0.0
    for count_value in no_hook_sequence_items(counts):
        count, count_reason = no_hook_finite_float(count_value, default=0.0, reason="invalid_entropy_count")
        if count_reason or count <= 0:
            continue
        p = count / total_f
        ent -= p * math.log2(p + 1e-12)
    return ent

def tag_entropy(tags: object) -> float:
    """Return Shannon entropy for semantic tag sequences without scanner state."""
    values: list[str] = []
    for tag in no_hook_sequence_items(tags):
        text, reason = no_hook_text(tag, missing_reason="missing_entropy_tag", unsupported_reason="invalid_entropy_tag")
        if not reason and text:
            values.append(text)
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values) + 0.0
    ent = 0.0
    for _tag, count in no_hook_mapping_items(counts, allow_dict_subclass=True) or ():
        probability = count / total
        ent -= probability * math.log2(probability + 1e-09)
    return max(0.0, ent)


def strict_fast_entropy(data: bytes | bytearray | memoryview | None) -> float:
    """Public direct-import-safe entropy for bounded strict-fast byte checks."""
    return shannon_entropy_bytes(data)


__all__ = ("entropy_from_counts", "shannon_entropy_bytes", "strict_fast_entropy", "tag_entropy")
