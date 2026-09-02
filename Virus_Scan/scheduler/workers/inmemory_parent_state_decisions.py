"""Replayable parent-side in-memory worker state decisions."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkerJobRecordDecision:
    """Decision for resolving an owned scheduler job record."""

    record: dict[str, object] | None
    accepted: bool
    reason: str


@dataclass(frozen=True)
class WorkerTimestampDecision:
    """Decision for scheduler worker timestamp materialization."""

    value: float
    accepted: bool
    reason: str


@dataclass(frozen=True)
class WorkerStateApplyDecision:
    """Decision for applying parent-side worker state transitions."""

    applied: bool
    reason: str


__all__ = (
    "WorkerJobRecordDecision",
    "WorkerTimestampDecision",
    "WorkerStateApplyDecision",
)
