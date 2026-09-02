"""Immutable worker identity, snapshot, and result contracts."""
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
class WorkerIdentity:
    worker_id: str
    pid: int = 0
    generation: int = 0

    def __post_init__(self) -> None:
        worker_id, _worker_id_issue = contract_text(self.worker_id, field_name="worker_id", default="")
        pid, _pid_issue = contract_int(self.pid, field_name="pid", default=0)
        generation, _generation_issue = contract_int(self.generation, field_name="generation", default=0, minimum=0)
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "pid", pid)
        object.__setattr__(self, "generation", generation)

    def as_dict(self) -> dict[str, object]:
        return {"worker_id": self.worker_id, "pid": self.pid, "generation": self.generation}

    @classmethod
    def from_mapping(cls, value: object) -> "WorkerIdentity":
        return cls(
            worker_id=contract_mapping_value(value, "worker_id", default=""),
            pid=contract_mapping_value(value, "pid", default=0),
            generation=contract_mapping_value(value, "generation", default=0),
        )


@dataclass(frozen=True, slots=True)
class WorkerSnapshot:
    live_count: int = 0
    workers: tuple[Mapping[str, object], ...] = ()
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        live_count, live_count_issue = contract_int(self.live_count, field_name="live_count", default=0, minimum=0)
        workers, workers_issue = contract_sequence(self.workers, field_name="workers")
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        object.__setattr__(self, "live_count", live_count)
        object.__setattr__(self, "workers", immutable_snapshot_tuple(merge_contract_issues(workers, workers_issue)))
        object.__setattr__(self, "evidence", immutable_snapshot_tuple(merge_contract_issues(evidence_items, live_count_issue, evidence_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "live_count": self.live_count,
            "workers": materialize_scheduler_mapping(self.workers),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "WorkerSnapshot":
        return cls(
            live_count=contract_mapping_value(value, "live_count", default=0),
            workers=contract_mapping_value(value, "workers", default=()),
            evidence=contract_mapping_value(value, "evidence", default=()),
        )


@dataclass(frozen=True, slots=True)
class WorkerResult:
    identity: WorkerIdentity
    success: bool = False
    result: Mapping[str, object] = field(default_factory=lambda: immutable_snapshot_mapping({}))
    failures: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.identity, WorkerIdentity):
            exception_message = "WorkerResult requires WorkerIdentity"
            raise TypeError(exception_message)
        success, success_issue = contract_bool(self.success, field_name="success", default=False)
        failures, failures_issue = contract_sequence(self.failures, field_name="failures")
        object.__setattr__(self, "success", success)
        object.__setattr__(self, "result", immutable_snapshot_mapping(self.result, field_name="result"))
        object.__setattr__(self, "failures", immutable_snapshot_tuple(merge_contract_issues(failures, success_issue, failures_issue)))

    def as_dict(self) -> dict[str, object]:
        return {
            "identity": self.identity.as_dict(),
            "success": self.success,
            "result": materialize_scheduler_mapping(self.result),
            "failures": materialize_scheduler_mapping(self.failures),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "WorkerResult":
        return cls(
            identity=WorkerIdentity.from_mapping(contract_mapping_value(value, "identity", default={}) or {}),
            success=contract_mapping_value(value, "success", default=False),
            result=contract_mapping_value(value, "result", default={}),
            failures=contract_mapping_value(value, "failures", default=()),
        )


__all__ = ("WorkerIdentity", "WorkerResult", "WorkerSnapshot")
