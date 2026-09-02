"""Scanner-owned binary raw escalation anchor policy.

This module replaces the Phase 10 private dependency on detection-owned
dangerous-anchor heuristics. It uses the immutable binary policy snapshot and
returns deterministic tag evidence without mutating detector state.
"""

from __future__ import annotations

from Virus_Scan.scanners.config import load_binary_policy_snapshot
from Virus_Scan.utils.tagging import normalize_tags

_BINARY_POLICY = load_binary_policy_snapshot()


def binary_raw_dangerous_anchor_hits(tags: object) -> tuple[str, ...]:
    """Return scanner-owned dangerous anchors present in raw binary tags."""
    normalized = {tag.strip().lower() for tag in normalize_tags(tags) if tag.strip()}
    anchors = set(_BINARY_POLICY.raw_escalation_dangerous_anchor_tags)
    return tuple(sorted(normalized & anchors))


__all__ = ("binary_raw_dangerous_anchor_hits",)
