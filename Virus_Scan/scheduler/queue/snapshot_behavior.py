"""Immutable queue behavior snapshot and integrity validation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_items, scheduler_mapping_value
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text
from Virus_Scan.scheduler.queue.snapshot_behavior_support import (
    SNAPSHOT_ALIASES,
    UNKNOWN_PHASE,
    snapshot_count,
    snapshot_issue,
    snapshot_message_int,
    snapshot_message_text,
    snapshot_optional_message_int,
)


@dataclass(frozen=True)
class QueueBehaviorSnapshot:
    phase: str
    pending: int
    claimed: int
    running: int
    completed: int
    failed: int
    quarantined: int
    duplicate_count: int
    invalid_record_count: int
    orphan_lock_count: int
    emitted_result_count: int = 0
    finalized_count: int = 0
    total: int | None = None
    input_evidence: tuple[Mapping[str, object], ...] = ()

    @classmethod
    def from_counts(cls, phase: str, counts: Mapping[str, object]) -> "QueueBehaviorSnapshot":
        evidence: tuple[Mapping[str, object], ...] = ()
        phase_text, phase_reason = scheduler_text(
            phase,
            replacement_text=UNKNOWN_PHASE,
            unsupported_reason="queue_snapshot_phase_rejected",
        )
        if phase_reason or phase_text == "":
            evidence += (
                snapshot_issue(
                    "phase", phase, phase_reason or "queue_snapshot_phase_blank"
                ),
            )
            phase_text = UNKNOWN_PHASE
        if scheduler_mapping_items(counts) is None:
            evidence += (
                snapshot_issue(
                    "counts", counts, "queuesnapshot_counts_mapping_rejected"
                ),
            )
            counts = {}
        values: dict[str, int] = {}
        for field_name, keys in SNAPSHOT_ALIASES:
            values[field_name], issue = snapshot_count(counts, field_name, *keys)
            evidence += issue
        total = None
        if scheduler_mapping_value(counts, "total") is not None:
            total, issue = snapshot_count(counts, "total", "total")
            evidence += issue
        return cls(
            phase=phase_text,
            total=total,
            input_evidence=immutable_tuple(evidence),
            **values,
        )

    def as_dict(self) -> dict[str, object]:
        payload = {
            field: scheduler_exact_attr(self, field, owner_type=QueueBehaviorSnapshot)
            for field in (
                "phase",
                "pending",
                "claimed",
                "running",
                "completed",
                "failed",
                "quarantined",
                "duplicate_count",
                "invalid_record_count",
                "orphan_lock_count",
                "emitted_result_count",
                "finalized_count",
            )
        }
        if self.total is not None:
            payload["total"] = self.total
        if self.input_evidence:
            payload["input_evidence"] = [
                materialize_scheduler_mapping(item) for item in self.input_evidence
            ]
        return payload

    def assert_valid(self, previous: "QueueBehaviorSnapshot | None" = None) -> None:
        phase = snapshot_message_text(self.phase)
        _assert_snapshot_progress(self, previous, phase)
        _assert_snapshot_finalization(self, phase)
        _assert_snapshot_clean(self, phase)


def _assert_snapshot_progress(
    snapshot: QueueBehaviorSnapshot,
    previous: QueueBehaviorSnapshot | None,
    phase: str,
) -> None:
    pending = snapshot_message_int(snapshot.pending, "pending")
    running = snapshot_message_int(snapshot.running, "running")
    completed = snapshot_message_int(snapshot.completed, "completed")
    failed = snapshot_message_int(snapshot.failed, "failed")
    total = snapshot_optional_message_int(snapshot.total, "total")
    if previous is not None:
        previous_completed = snapshot_message_int(previous.completed, "previous_completed")
        previous_failed = snapshot_message_int(previous.failed, "previous_failed")
        previous_total = snapshot_optional_message_int(previous.total, "previous_total")
        if completed < previous_completed:
            raise RuntimeError("queue counter regression: files_done decreased during " + phase)
        if failed < previous_failed:
            raise RuntimeError("queue counter regression: files_failed decreased during " + phase)
        if previous_total is not None and total is not None and total != previous_total:
            raise RuntimeError("queue total changed without explicit expansion record during " + phase)
    if total is not None and pending + running + completed + failed > total:
        raise RuntimeError("queue counter overflow during " + phase + ": pending+running+completed+failed exceeds total")


def _assert_snapshot_finalization(snapshot: QueueBehaviorSnapshot, phase: str) -> None:
    if phase != "finalize":
        return
    finalized = snapshot_message_int(snapshot.finalized_count, "finalized_count")
    emitted = snapshot_message_int(snapshot.emitted_result_count, "emitted_result_count")
    if finalized != emitted:
        raise RuntimeError("queue finalization mismatch during " + phase + ": finalized=" + int.__str__(finalized) + " emitted=" + int.__str__(emitted))
    pending = snapshot_message_int(snapshot.pending, "pending")
    claimed = snapshot_message_int(snapshot.claimed, "claimed")
    running = snapshot_message_int(snapshot.running, "running")
    if pending != 0 or claimed != 0 or running != 0:
        raise RuntimeError("queue finalization has unfinished scheduler work during " + phase + ": pending=" + int.__str__(pending) + " claimed=" + int.__str__(claimed) + " running=" + int.__str__(running))


def _assert_snapshot_clean(snapshot: QueueBehaviorSnapshot, phase: str) -> None:
    duplicate_count = snapshot_message_int(snapshot.duplicate_count, "duplicate_count")
    invalid_record_count = snapshot_message_int(snapshot.invalid_record_count, "invalid_record_count")
    orphan_lock_count = snapshot_message_int(snapshot.orphan_lock_count, "orphan_lock_count")
    if duplicate_count != 0:
        raise RuntimeError("duplicate queue records remain during " + phase + ": " + int.__str__(duplicate_count))
    if invalid_record_count != 0:
        raise RuntimeError("invalid queue records remain during " + phase + ": " + int.__str__(invalid_record_count))
    if phase == "finalize" and orphan_lock_count != 0:
        raise RuntimeError("orphan queue locks remain during " + phase + ": " + int.__str__(orphan_lock_count))


def validate_queue_integrity(
    previous_snapshot: object,
    current_snapshot: object,
    *,
    allow_total_expansion: bool = False,
) -> QueueBehaviorSnapshot:
    previous = previous_snapshot if type(previous_snapshot) is QueueBehaviorSnapshot else None
    current = current_snapshot if type(current_snapshot) is QueueBehaviorSnapshot else QueueBehaviorSnapshot.from_counts("unknown", current_snapshot)
    previous_total = snapshot_optional_message_int(previous.total, "previous_total") if previous is not None else None
    current_total = snapshot_optional_message_int(current.total, "total")
    if previous is not None and allow_total_expansion and previous_total is not None and current_total is not None and current_total >= previous_total:
        previous = QueueBehaviorSnapshot.from_counts(previous.phase, {**previous.as_dict(), "total": current_total})
    current.assert_valid(previous)
    return current


__all__ = ("QueueBehaviorSnapshot", "validate_queue_integrity")
