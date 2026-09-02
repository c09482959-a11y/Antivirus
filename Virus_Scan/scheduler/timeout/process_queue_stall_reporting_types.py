"""Typed contracts for process-queue stall reporting."""
from __future__ import annotations

from typing import Callable, Mapping, NamedTuple, TypeAlias

SchedulerPidValue: TypeAlias = int | Mapping[str, object]
SchedulerEvidence: TypeAlias = dict[str, object]
StallEvidenceRecord: TypeAlias = Mapping[str, object]
StallEvidenceList: TypeAlias = list[StallEvidenceRecord]
StallIssueRecorder: TypeAlias = Callable[..., object]
TerminationSnapshot: TypeAlias = dict[str, object]


class PublicTerminationSnapshotDecision(NamedTuple):
    available: bool
    snapshot: TerminationSnapshot
    reason: str


__all__ = (
    "PublicTerminationSnapshotDecision",
    "SchedulerEvidence",
    "SchedulerPidValue",
    "StallEvidenceList",
    "StallIssueRecorder",
    "TerminationSnapshot",
)
