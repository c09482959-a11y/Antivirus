"""Canonical immutable queue snapshot and phase-ledger facade."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.queue.phase_order import validate_queue_phase_transition
from Virus_Scan.scheduler.queue.snapshot_behavior import (
    QueueBehaviorSnapshot,
    validate_queue_integrity,
)

_QUEUE_PHASE_LEDGER_REQUIRES_IMMUTABLE_SNAPSHOTS = "scheduler queue phase ledger requires immutable snapshots"
_QUEUE_PHASE_LEDGER_MISSING_PHASES = "scheduler queue phase ledger missing phases"


@dataclass(frozen=True)
class QueuePhaseLedger:
    """Immutable ordered scheduler snapshot ledger."""

    snapshots: tuple[QueueBehaviorSnapshot, ...]

    def __post_init__(self) -> None:
        snapshots = (
            no_hook_sequence_items(self.snapshots)
            if type(self.snapshots) in (tuple, list)
            else ()
        )
        object.__setattr__(
            self,
            "snapshots",
            tuple(item for item in snapshots if type(item) is QueueBehaviorSnapshot),
        )

    def with_snapshot(self, snapshot: QueueBehaviorSnapshot) -> "QueuePhaseLedger":
        if type(snapshot) is not QueueBehaviorSnapshot:
            raise RuntimeError(_QUEUE_PHASE_LEDGER_REQUIRES_IMMUTABLE_SNAPSHOTS)
        previous = self.snapshots[-1] if self.snapshots else None
        if previous is not None:
            validate_queue_phase_transition(previous.phase, snapshot.phase)
            validate_queue_integrity(previous, snapshot)
        else:
            snapshot.assert_valid(None)
        return QueuePhaseLedger((*self.snapshots, snapshot))

    def assert_contains(self, required_phases: Sequence[str]) -> None:
        seen = {
            str.__str__(snapshot.phase)
            if type(snapshot.phase) is str and snapshot.phase
            else "unknown"
            for snapshot in self.snapshots
        }
        required = tuple(
            str.__str__(item) if type(item) is str and item else "unknown"
            for item in no_hook_sequence_items(required_phases)
        )
        missing = tuple(phase for phase in required if phase not in seen)
        if missing:
            safe_missing = tuple(str.__str__(item) for item in missing if type(item) is str and item)
            if safe_missing:
                raise RuntimeError(_QUEUE_PHASE_LEDGER_MISSING_PHASES + ": " + str.join(", ", safe_missing))
            raise RuntimeError(_QUEUE_PHASE_LEDGER_MISSING_PHASES)

    def as_dict(self) -> dict[str, object]:
        return {"snapshots": [snapshot.as_dict() for snapshot in self.snapshots]}


_validate_queue_integrity = validate_queue_integrity

__all__ = (
    "QueueBehaviorSnapshot",
    "QueuePhaseLedger",
    "validate_queue_integrity",
)
