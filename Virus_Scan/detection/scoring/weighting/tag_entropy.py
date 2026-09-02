"""Detection-owned tag entropy helpers for scoring."""
from __future__ import annotations

from collections import Counter
import math
from typing import Iterable

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items


def tag_entropy(tags: Iterable[object] | None) -> float:
    """Return Shannon entropy for already-normalized detection tags.

    This preserves the former scanner entropy contract behavior used by
    detection scoring without importing scanner-owned binary entropy code.
    The helper measures semantic tag distribution only; byte/file entropy
    remains scanner-owned.
    """
    values = no_hook_sequence_items(tags)
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    entropy = 0.0
    count_items = no_hook_mapping_items(counts, allow_dict_subclass=True)
    if count_items is None:
        return 0.0
    for _tag, count in count_items:
        probability = count / total
        entropy -= probability * math.log2(probability + 1e-09)
    return entropy


__all__ = ("tag_entropy",)
