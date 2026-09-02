"""Immutable final scheduler result contract."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_mapping_items,
    contract_mapping_value,
    contract_sequence,
    contract_text,
    merge_contract_issues,
)
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.phase_output import SchedulerPhaseOutputLedger
from Virus_Scan.scheduler.contracts.queue_snapshot import QueueSnapshot
from Virus_Scan.scheduler.contracts.replay_result import ReplaySnapshot
from Virus_Scan.scheduler.contracts.retry_result import RetryDecision
from Virus_Scan.scheduler.contracts.timeout_result import TimeoutResult
from Virus_Scan.scheduler.contracts.worker_result import WorkerSnapshot
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_mapping

_SCHEDULER_RESULT_EVIDENCE_REQUIRES_EVIDENCE_RECORD = "SchedulerResult evidence requires SchedulerEvidenceRecord"


def _require_scheduler_result_evidence_record(record: object) -> SchedulerEvidenceRecord:
    if not isinstance(record, SchedulerEvidenceRecord):
        raise TypeError(_SCHEDULER_RESULT_EVIDENCE_REQUIRES_EVIDENCE_RECORD)
    return record


@dataclass(frozen=True, slots=True)
class SchedulerResult:
    status: str = "ok"
    results: Mapping[str, object] = field(default_factory=lambda: immutable_snapshot_mapping({}))
    summary: Mapping[str, object] = field(default_factory=lambda: immutable_snapshot_mapping({}))
    evidence: tuple[SchedulerEvidenceRecord, ...] = ()
    queue_snapshot: QueueSnapshot | None = None
    worker_snapshot: WorkerSnapshot | None = None
    timeout_result: TimeoutResult | None = None
    retry_decision: RetryDecision | None = None
    replay_snapshot: ReplaySnapshot | None = None
    phase_outputs: SchedulerPhaseOutputLedger | None = None

    def __post_init__(self) -> None:
        status, status_issue = contract_text(self.status, field_name="status", default="ok")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "results", immutable_snapshot_mapping(self.results, field_name="results"))
        object.__setattr__(self, "summary", immutable_snapshot_mapping(self.summary, field_name="summary"))
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        evidence = [_require_scheduler_result_evidence_record(record) for record in evidence_items]
        evidence.extend(
            SchedulerEvidenceRecord(
                stage="scheduler_result_contract",
                state="degraded",
                error_category="scheduler_contract_field_rejected",
                error_source="scheduler.contracts.scheduler_result",
                message="scheduler result field rejected without caller hooks",
                context=issue,
            )
            for issue in merge_contract_issues(status_issue, evidence_issue)
            if type(issue) is dict
        )
        object.__setattr__(self, "evidence", tuple(evidence))
        self._require_optional("queue_snapshot", self.queue_snapshot, QueueSnapshot)
        self._require_optional("worker_snapshot", self.worker_snapshot, WorkerSnapshot)
        self._require_optional("timeout_result", self.timeout_result, TimeoutResult)
        self._require_optional("retry_decision", self.retry_decision, RetryDecision)
        self._require_optional("replay_snapshot", self.replay_snapshot, ReplaySnapshot)
        self._require_optional("phase_outputs", self.phase_outputs, SchedulerPhaseOutputLedger)

    @staticmethod
    def _require_optional(name: str, value: object, expected_type: type[object]) -> None:
        if value is not None and not isinstance(value, expected_type):
            raise TypeError("SchedulerResult " + name + " requires " + expected_type.__name__)

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "results": materialize_scheduler_mapping(self.results),
            "summary": materialize_scheduler_mapping(self.summary),
            "evidence": [record.as_dict() for record in self.evidence],
            "snapshots": {
                "queue": None if self.queue_snapshot is None else self.queue_snapshot.as_dict(),
                "worker": None if self.worker_snapshot is None else self.worker_snapshot.as_dict(),
                "timeout": None if self.timeout_result is None else self.timeout_result.as_dict(),
                "retry": None if self.retry_decision is None else self.retry_decision.as_dict(),
                "replay": None if self.replay_snapshot is None else self.replay_snapshot.as_dict(),
            },
            "phase_outputs": None if self.phase_outputs is None else self.phase_outputs.as_dict(),
        }

    def as_replay_snapshot(self, replay_id: str = "scheduler-result") -> ReplaySnapshot:
        """Materialize this final result as an immutable replay boundary snapshot."""
        records: tuple[Mapping[str, object], ...] = (self.as_dict(),)
        if self.phase_outputs is not None:
            records = records + self.phase_outputs.as_replay_records()
        return ReplaySnapshot(replay_id=replay_id, records=records, evidence=tuple(record.as_dict() for record in self.evidence))

    @classmethod
    def from_mapping(cls, value: object) -> "SchedulerResult":
        snapshots: object = contract_mapping_value(value, "snapshots", default={}) or {}
        if contract_mapping_items(snapshots) is None:
            snapshots = {}
        evidence_items, _evidence_issue = contract_sequence(contract_mapping_value(value, "evidence", default=()), field_name="evidence")
        queue_snapshot = contract_mapping_value(snapshots, "queue")
        worker_snapshot = contract_mapping_value(snapshots, "worker")
        timeout_result = contract_mapping_value(snapshots, "timeout")
        retry_decision = contract_mapping_value(snapshots, "retry")
        replay_snapshot = contract_mapping_value(snapshots, "replay")
        phase_outputs = contract_mapping_value(value, "phase_outputs")
        return cls(
            status=contract_mapping_value(value, "status", default="ok"),
            results=contract_mapping_value(value, "results", default={}),
            summary=contract_mapping_value(value, "summary", default={}),
            evidence=tuple(SchedulerEvidenceRecord.from_mapping(record) for record in evidence_items),
            queue_snapshot=None if queue_snapshot is None else QueueSnapshot.from_mapping(queue_snapshot),
            worker_snapshot=None if worker_snapshot is None else WorkerSnapshot.from_mapping(worker_snapshot),
            timeout_result=None if timeout_result is None else TimeoutResult.from_mapping(timeout_result),
            retry_decision=None if retry_decision is None else RetryDecision.from_mapping(retry_decision),
            replay_snapshot=None if replay_snapshot is None else ReplaySnapshot.from_mapping(replay_snapshot),
            phase_outputs=None if phase_outputs is None else SchedulerPhaseOutputLedger.from_mapping(phase_outputs),
        )


__all__ = ("SchedulerResult",)
