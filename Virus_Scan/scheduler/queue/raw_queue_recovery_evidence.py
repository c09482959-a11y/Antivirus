"""Replayable evidence records for raw queue recovery progress decisions."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RawStageProgressPathKey:
    """Path-key materialization result for raw-stage progress state."""

    key: str
    available: bool
    reason: str = ""


@dataclass(frozen=True)
class RawStageProgressCountEvidence:
    """Count materialization result for raw-stage progress accounting."""

    total: int
    available: bool
    reason: str = ""


@dataclass(frozen=True)
class RawStageProgressStateEvidence:
    """Previous-state materialization result for raw-stage progress accounting."""

    previous_count: int | None
    previous_time: float
    available: bool
    reason: str = ""
