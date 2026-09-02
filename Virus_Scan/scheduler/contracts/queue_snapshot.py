"""Immutable queue snapshot and queue result contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_bool,
    contract_int,
    contract_mapping_value,
    contract_sequence,
    contract_text,
    merge_contract_issues,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_snapshots import (
    immutable_snapshot_mapping,
    immutable_snapshot_tuple,
)


@dataclass(frozen=True, slots=True)
class QueueSnapshot:
    phase: str = "unknown"
    pending: int = 0
    active: int = 0
    done: int = 0
    failed: int = 0
    metadata: Mapping[str, object] = field(default_factory=lambda: immutable_snapshot_mapping({}))
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        phase, phase_issue = contract_text(self.phase, field_name="phase", default="unknown")
        pending, pending_issue = contract_int(self.pending, field_name="pending", default=0, minimum=0)
        active, active_issue = contract_int(self.active, field_name="active", default=0, minimum=0)
        done, done_issue = contract_int(self.done, field_name="done", default=0, minimum=0)
        failed, failed_issue = contract_int(self.failed, field_name="failed", default=0, minimum=0)
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "pending", pending)
        object.__setattr__(self, "active", active)
        object.__setattr__(self, "done", done)
        object.__setattr__(self, "failed", failed)
        object.__setattr__(self, "metadata", immutable_snapshot_mapping(self.metadata, field_name="metadata"))
        object.__setattr__(self, "evidence", immutable_snapshot_tuple(merge_contract_issues(evidence_items, phase_issue, pending_issue, active_issue, done_issue, failed_issue, evidence_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "pending": self.pending,
            "active": self.active,
            "done": self.done,
            "failed": self.failed,
            "metadata": materialize_scheduler_mapping(self.metadata),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "QueueSnapshot":
        return cls(
            phase=contract_mapping_value(value, "phase", default="unknown"),
            pending=contract_mapping_value(value, "pending", default=0),
            active=contract_mapping_value(value, "active", default=0),
            done=contract_mapping_value(value, "done", default=0),
            failed=contract_mapping_value(value, "failed", default=0),
            metadata=contract_mapping_value(value, "metadata", default={}),
            evidence=contract_mapping_value(value, "evidence", default=()),
        )


@dataclass(frozen=True, slots=True)
class QueueIntegrityResult:
    ok: bool
    snapshot: QueueSnapshot
    failures: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, QueueSnapshot):
            exception_message = "QueueIntegrityResult requires QueueSnapshot"
            raise TypeError(exception_message)
        ok, ok_issue = contract_bool(self.ok, field_name="ok", default=False)
        failures, failures_issue = contract_sequence(self.failures, field_name="failures")
        object.__setattr__(self, "ok", ok)
        object.__setattr__(self, "failures", immutable_snapshot_tuple(merge_contract_issues(failures, ok_issue, failures_issue)))

    def as_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "snapshot": self.snapshot.as_dict(), "failures": materialize_scheduler_mapping(self.failures)}

    @classmethod
    def from_mapping(cls, value: object) -> "QueueIntegrityResult":
        return cls(ok=contract_mapping_value(value, "ok", default=False), snapshot=QueueSnapshot.from_mapping(contract_mapping_value(value, "snapshot", default={}) or {}), failures=contract_mapping_value(value, "failures", default=()))


@dataclass(frozen=True, slots=True)
class QueueRecoveryResult:
    recovered: int = 0
    orphaned: int = 0
    snapshot: QueueSnapshot | None = None
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        recovered, recovered_issue = contract_int(self.recovered, field_name="recovered", default=0, minimum=0)
        orphaned, orphaned_issue = contract_int(self.orphaned, field_name="orphaned", default=0, minimum=0)
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        object.__setattr__(self, "recovered", recovered)
        object.__setattr__(self, "orphaned", orphaned)
        object.__setattr__(self, "evidence", immutable_snapshot_tuple(merge_contract_issues(evidence_items, recovered_issue, orphaned_issue, evidence_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "recovered": self.recovered,
            "orphaned": self.orphaned,
            "snapshot": None if self.snapshot is None else self.snapshot.as_dict(),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "QueueRecoveryResult":
        snapshot = contract_mapping_value(value, "snapshot")
        return cls(
            recovered=contract_mapping_value(value, "recovered", default=0),
            orphaned=contract_mapping_value(value, "orphaned", default=0),
            snapshot=None if snapshot is None else QueueSnapshot.from_mapping(snapshot),
            evidence=contract_mapping_value(value, "evidence", default=()),
        )


@dataclass(frozen=True, slots=True)
class QueueMergeResult:
    merged: Mapping[str, object] = field(default_factory=lambda: immutable_snapshot_mapping({}))
    missing_results: tuple[Mapping[str, object], ...] = ()
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        missing_results, missing_results_issue = contract_sequence(self.missing_results, field_name="missing_results")
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        object.__setattr__(self, "merged", immutable_snapshot_mapping(self.merged, field_name="merged"))
        object.__setattr__(self, "missing_results", immutable_snapshot_tuple(merge_contract_issues(missing_results, missing_results_issue)))
        object.__setattr__(self, "evidence", immutable_snapshot_tuple(merge_contract_issues(evidence_items, evidence_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "merged": materialize_scheduler_mapping(self.merged),
            "missing_results": materialize_scheduler_mapping(self.missing_results),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "QueueMergeResult":
        return cls(
            merged=contract_mapping_value(value, "merged", default={}),
            missing_results=contract_mapping_value(value, "missing_results", default=()),
            evidence=contract_mapping_value(value, "evidence", default=()),
        )


__all__ = ("QueueIntegrityResult", "QueueMergeResult", "QueueRecoveryResult", "QueueSnapshot")
