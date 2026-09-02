"""Canonical immutable queue result-publication and finalization ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
)
from Virus_Scan.scheduler.api import contracts as scheduler_contracts
from Virus_Scan.scheduler.api.contracts import SchedulerTypeContractError
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text
from Virus_Scan.scheduler.queue.recovery_contracts import QueueWorkerFailureAccounting
from Virus_Scan.scheduler.queue.snapshots import QueuePhaseLedger
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_file_identity_for_path as _queue_file_identity_for_path

_MALFORMED_SCHEDULER_RESULT_RECORD = "malformed scheduler result record"
_SCHEDULER_RESULT_MISSING_JOB_IDENTITY = "scheduler result missing job identity"
_SCHEDULER_RESULT_MISSING_FILE_PATH = "scheduler result missing file path"
_FINALIZATION_MISSING_CANONICAL_PHASE_LEDGER = "scheduler finalization state missing canonical phase ledger"
_FINALIZATION_MISSING_CANONICAL_PUBLICATION_STATE = "scheduler finalization state missing canonical publication state"
_FINALIZATION_NEGATIVE_RESULT_ACCOUNTING = "scheduler finalization state has negative result accounting"
_FINALIZATION_PUBLICATION_COUNT_MISMATCH = "scheduler finalization publication count does not match emitted result count"
_FINALIZATION_WORKER_ACCOUNTING_NOT_CANONICAL = "scheduler finalization worker accounting is not immutable/canonical"
_FINALIZATION_MUST_END_WITH_FINALIZE = "scheduler finalization state must end with finalize snapshot"


def _publication_mapping(result: object) -> dict[object, object]:
    items = no_hook_mapping_items(result)
    if items is None:
        raise RuntimeError(_MALFORMED_SCHEDULER_RESULT_RECORD)
    return dict(items)

def _publication_reason(field_name: object, suffix: str) -> str:
    field_text = "field"
    if type(field_name) is str:
        stripped = str.__str__(field_name).strip()
        if stripped:
            field_text = stripped
    return "scheduler_publication_" + field_text + "_" + suffix


def _publication_text(value: object, *, field_name: str) -> str:
    text, reason = scheduler_text(
        value,
        unsupported_reason=_publication_reason(field_name, "rejected"),
    )
    if reason or text.strip() == "":
        raise RuntimeError(reason or _publication_reason(field_name, "missing"))
    return text.strip()


def _result_publication_identity(result: Mapping[str, object] | None) -> str:
    snapshot = _publication_mapping(result)
    for key in ("job_id", "queue_id", "raw_job_id", "id"):
        value = dict.get(snapshot, key)
        if value is None:
            continue
        return _publication_text(value, field_name=key)
    for key in ("file", "path", "file_path"):
        value = dict.get(snapshot, key)
        if value is None:
            continue
        file_path = _publication_text(value, field_name=key)
        return _queue_file_identity_for_path(file_path)
    raise RuntimeError(_SCHEDULER_RESULT_MISSING_JOB_IDENTITY)


def _result_publication_file_identity(result: Mapping[str, object] | None) -> str:
    snapshot = _publication_mapping(result)
    file_path = ""
    for key in ("file", "path", "file_path"):
        value = dict.get(snapshot, key)
        if value is not None:
            file_path = _publication_text(value, field_name=key)
            break
    if file_path == "":
        raise RuntimeError(_SCHEDULER_RESULT_MISSING_FILE_PATH)
    archive_identity = ""
    for key in ("archive_child_identity", "archive_member", "container_child"):
        value = dict.get(snapshot, key)
        if value is not None:
            archive_identity = _publication_text(value, field_name=key)
            break
    base_identity = _queue_file_identity_for_path(file_path)
    return base_identity + "::" + archive_identity if archive_identity else base_identity


@dataclass(frozen=True)
class QueuePublicationState:
    """Immutable scheduler result publication state for duplicate and ownership enforcement."""

    job_identities: frozenset[str]
    file_identities: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "job_identities",
            _publication_identity_set(self.job_identities, field_name="job_identity"),
        )
        object.__setattr__(
            self,
            "file_identities",
            _publication_identity_set(self.file_identities, field_name="file_identity"),
        )

    @classmethod
    def empty(cls) -> "QueuePublicationState":
        return cls(frozenset(), frozenset())

    def with_publication(self, result: Mapping[str, object]) -> "QueuePublicationState":
        job_identity = _result_publication_identity(result)
        file_identity = _result_publication_file_identity(result)
        if job_identity in self.job_identities:
            raise RuntimeError("duplicate scheduler result publication: " + job_identity)
        if file_identity in self.file_identities:
            raise RuntimeError("duplicate scheduler file result publication: " + file_identity)
        return QueuePublicationState(
            frozenset((*self.job_identities, job_identity)),
            frozenset((*self.file_identities, file_identity)),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "job_identities": sorted(self.job_identities),
            "file_identities": sorted(self.file_identities),
        }


@dataclass(frozen=True)
class QueueRunFinalizationState:
    """Immutable final scheduler run state tying phases, publications, and worker cleanup together."""

    phase_ledger: QueuePhaseLedger
    publication_state: QueuePublicationState
    worker_failures: tuple[QueueWorkerFailureAccounting, ...]
    emitted_result_count: int
    finalized_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_failures", immutable_tuple(self.worker_failures))
        emitted, emitted_reason = scheduler_int(
            self.emitted_result_count,
            default=0,
            minimum=0,
            reason="scheduler_emitted_result_count_rejected",
        )
        finalized, finalized_reason = scheduler_int(
            self.finalized_count,
            default=0,
            minimum=0,
            reason="scheduler_finalized_count_rejected",
        )
        if emitted_reason or finalized_reason:
            raise scheduler_contracts.SchedulerFinalizationCountContractError(emitted_reason or finalized_reason)
        object.__setattr__(self, "emitted_result_count", emitted)
        object.__setattr__(self, "finalized_count", finalized)

    def assert_valid(self) -> None:
        if not isinstance(self.phase_ledger, QueuePhaseLedger):
            raise TypeError(_FINALIZATION_MISSING_CANONICAL_PHASE_LEDGER)
        if not isinstance(self.publication_state, QueuePublicationState):
            raise TypeError(_FINALIZATION_MISSING_CANONICAL_PUBLICATION_STATE)
        if self.emitted_result_count < 0 or self.finalized_count < 0:
            raise RuntimeError(_FINALIZATION_NEGATIVE_RESULT_ACCOUNTING)
        if self.emitted_result_count != self.finalized_count:
            raise scheduler_contracts.SchedulerFinalizationCountMismatchError(
                self.emitted_result_count,
                self.finalized_count,
            )
        if len(self.publication_state.job_identities) != self.emitted_result_count:
            raise RuntimeError(_FINALIZATION_PUBLICATION_COUNT_MISMATCH)
        for record in self.worker_failures:
            if not isinstance(record, QueueWorkerFailureAccounting):
                raise SchedulerTypeContractError(_FINALIZATION_WORKER_ACCOUNTING_NOT_CANONICAL)
            record.assert_valid()
        self.phase_ledger.assert_contains(("planning", "enqueue", "dispatch", "collect", "finalize"))
        if self.phase_ledger.snapshots[-1].phase != "finalize":
            raise RuntimeError(_FINALIZATION_MUST_END_WITH_FINALIZE)

    def as_dict(self) -> dict[str, object]:
        self.assert_valid()
        return {
            "phase_ledger": self.phase_ledger.as_dict(),
            "publication_state": self.publication_state.as_dict(),
            "worker_failures": [record.as_dict() for record in self.worker_failures],
            "emitted_result_count": self.emitted_result_count,
            "finalized_count": self.finalized_count,
        }


def _publication_identity_set(value: object, *, field_name: str) -> frozenset[str]:
    if type(value) not in {tuple, list, set, frozenset}:
        raise ValueError(_publication_reason(field_name, "container_rejected"))
    return frozenset(_publication_text(item, field_name=field_name) for item in no_hook_sequence_items(value))
