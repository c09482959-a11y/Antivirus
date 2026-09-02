"""Direct-import-safe counter helpers shared by model, detection, and scanner callers."""
from __future__ import annotations

from typing import MutableMapping

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS


def increment_counter(counter_dict: MutableMapping[str, int], key: object, amount: int = 1) -> int:
    """Increment a caller-owned counter mapping with deterministic string keys."""
    normalized = str(key)
    try:
        counter_dict[normalized] = int(counter_dict.get(normalized, 0)) + int(amount)
    except IO_CONFIGURATION_ERRORS:
        counter_dict[normalized] = int(amount)
    return int(counter_dict[normalized])


__all__ = ("increment_counter",)
