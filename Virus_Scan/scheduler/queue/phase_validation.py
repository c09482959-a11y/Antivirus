"""Queue-owned validation helpers for scheduler phase boundaries."""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.api.contracts import SchedulerTypeContractError
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_text

from Virus_Scan.scheduler.queue.publication_state import (
    QueuePublicationState,
    _result_publication_file_identity,
    _result_publication_identity,
)
from Virus_Scan.scheduler.queue.recovery_contracts import QueueRecoveryDecision, QueueWorkerFailureAccounting
from Virus_Scan.scheduler.queue.snapshots import QueueBehaviorSnapshot, validate_queue_integrity as _validate_queue_integrity

_SEQ_TYPES = (list, tuple, set, frozenset)
_SCHEDULER_RECOVERY_DECISION_NOT_CANONICAL = "scheduler recovery decision is not immutable/canonical"
_SCHEDULER_WORKER_FAILURE_ACCOUNTING_NOT_CANONICAL = "scheduler worker failure accounting is not immutable/canonical"

def _owned_text_set(values: object, field_name: str) -> FrozenSet[str]:
    items = no_hook_sequence_items(values)
    if not items and values is not None and type(values) not in _SEQ_TYPES:
        items = (values,)
    return frozenset(
        text
        for item in items
        if (text := scheduler_evidence_text(item, missing_text="", field_name=field_name)).strip()
    )

def _owned_sequence(values: object, error_text: str) -> tuple[object, ...]:
    items = no_hook_sequence_items(values)
    if not items and values is not None and type(values) not in _SEQ_TYPES:
        raise RuntimeError(error_text)
    return items


@dataclass(frozen=True, slots=True)
class ResultPublicationValidationRequest:
    result: object
    known_jobs: object
    claimed_jobs: object
    published_identities: object
    worker_id: object = None
    worker_ownership: object = None
    published_file_identities: object = None


def validate_result_publication(
    request: ResultPublicationValidationRequest,
) -> object:
    """Reject duplicate, unknown, unclaimed, cross-worker, or duplicate-file scheduler results."""
    identity = _result_publication_identity(request.result)
    _result_publication_file_identity(request.result)
    known: FrozenSet[str] = _owned_text_set(request.known_jobs, "known_job")
    claimed: FrozenSet[str] = _owned_text_set(request.claimed_jobs, "claimed_job")
    published: FrozenSet[str] = _owned_text_set(request.published_identities, "published_identity")
    published_files: FrozenSet[str] = _owned_text_set(request.published_file_identities, "published_file_identity")
    if known and identity not in known:
        raise RuntimeError("scheduler result for unknown job: " + scheduler_evidence_text(identity, missing_text="", field_name="result_identity"))
    if claimed and identity not in claimed:
        raise RuntimeError("scheduler result for unclaimed job: " + scheduler_evidence_text(identity, missing_text="", field_name="result_identity"))
    if request.worker_id is not None:
        owner = scheduler_mapping_value(request.worker_ownership, identity, default=None)
        if owner is not None and scheduler_evidence_text(owner, missing_text="", field_name="worker_owner") != scheduler_evidence_text(request.worker_id, missing_text="", field_name="worker_id"):
            raise RuntimeError(
                "scheduler worker ownership mismatch for "
                + scheduler_evidence_text(identity, missing_text="", field_name="result_identity")
                + ": owner="
                + scheduler_evidence_text(owner, missing_text="", field_name="worker_owner")
                + " reporter="
                + scheduler_evidence_text(request.worker_id, missing_text="", field_name="worker_id")
            )
    QueuePublicationState(published, published_files).with_publication(request.result)
    return identity



def _validate_recovery_decision_batch(decisions: object) -> object:
    """Hard-fail if recovery emits duplicate or non-canonical decisions."""
    seen_jobs: set[str] = set()
    seen_workers: set[tuple[str, str]] = set()
    canonical = []
    for decision in _owned_sequence(decisions, "scheduler recovery decisions input rejected"):
        if not isinstance(decision, QueueRecoveryDecision):
            raise SchedulerTypeContractError(_SCHEDULER_RECOVERY_DECISION_NOT_CANONICAL)
        decision.assert_valid()
        if decision.job_id in seen_jobs:
            raise RuntimeError(
                "duplicate scheduler recovery decision for job: "
                + scheduler_evidence_text(decision.job_id, missing_text="", field_name="recovery_job_id")
            )
        worker_key = (decision.worker_id, decision.job_id)
        if worker_key in seen_workers:
            raise RuntimeError(
                "duplicate scheduler worker recovery accounting: "
                + scheduler_evidence_text(decision.worker_id, missing_text="", field_name="recovery_worker_id")
                + ":"
                + scheduler_evidence_text(decision.job_id, missing_text="", field_name="recovery_job_id")
            )
        seen_jobs.add(decision.job_id)
        seen_workers.add(worker_key)
        canonical.append(decision)
    return tuple(canonical)


def _validate_terminal_job_accounting(claimed_jobs: object, terminal_jobs: object, worker_accounting_records: object=()) -> object:
    """Verify every claimed scheduler job has an explicit terminal state or recovery accounting."""
    claimed = _owned_text_set(claimed_jobs, "claimed_job")
    terminal = _owned_text_set(terminal_jobs, "terminal_job")
    accounted = set()
    for record in _owned_sequence(worker_accounting_records, "scheduler worker accounting input rejected"):
        if not isinstance(record, QueueWorkerFailureAccounting):
            raise SchedulerTypeContractError(_SCHEDULER_WORKER_FAILURE_ACCOUNTING_NOT_CANONICAL)
        record.assert_valid()
        accounted.add(record.job_id)
    missing = sorted(claimed - terminal - accounted)
    if missing:
        raise RuntimeError("claimed scheduler jobs lack final state: " + ", ".join(missing))
    return True


__all__ = (
    'QueueBehaviorSnapshot',
    'ResultPublicationValidationRequest',
    '_validate_queue_integrity',
    '_validate_recovery_decision_batch',
    '_validate_terminal_job_accounting',
    'validate_result_publication',
)
