"""Replayable scheduler evidence collection decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord


@dataclass(frozen=True)
class SchedulerEvidenceRecordShapeDecision:
    """Decision for scheduler evidence-record shape checks."""

    looks_like: bool
    reason: str
    keys: tuple[str, ...]


@dataclass(frozen=True)
class SchedulerEvidenceSequenceDecision:
    """Decision for exact scheduler evidence source sequences."""

    items: tuple[object, ...] | None
    reason: str


@dataclass(frozen=True)
class SchedulerEvidenceMappingItemsDecision:
    """Decision for exact scheduler evidence mapping items."""

    items: tuple[tuple[object, object], ...] | None
    reason: str


@dataclass(frozen=True)
class SchedulerEvidenceNestedSourceDecision:
    """Decision for nested scheduler evidence source lookup."""

    found: bool
    source: object
    reason: str


@dataclass(frozen=True)
class SchedulerEvidenceSourceCollectionDecision:
    """Decision for one scheduler evidence source collection."""

    records: tuple[SchedulerEvidenceRecord, ...]
    reason: str


__all__ = (
    "SchedulerEvidenceMappingItemsDecision",
    "SchedulerEvidenceNestedSourceDecision",
    "SchedulerEvidenceRecordShapeDecision",
    "SchedulerEvidenceSequenceDecision",
    "SchedulerEvidenceSourceCollectionDecision",
)
