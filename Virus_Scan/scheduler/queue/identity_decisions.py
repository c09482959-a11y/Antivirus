"""Typed queue identity decisions for replayable sentinel replacements."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QueueJobNameDecision:
    accepted: bool
    normalized_name: str
    reason: str
    source_type: str


@dataclass(frozen=True, slots=True)
class IdentityIndexInvalidationDecision:
    succeeded: bool
    reason: str
    queue_dir_type: str


__all__ = (
    "IdentityIndexInvalidationDecision",
    "QueueJobNameDecision",
)
