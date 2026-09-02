"""Support decisions for bounded in-memory retry recovery."""
from __future__ import annotations

from typing import Mapping, MutableMapping, MutableSet

from Virus_Scan.scheduler.queue.inmemory_retry_contracts import InMemoryRetryDecision
from Virus_Scan.scheduler.queue.inmemory_retry_missing_record import (
    retry_duplicate_pending_evidence,
    retry_missing_record_evidence,
    retry_terminal_already_evidence,
)
from Virus_Scan.scheduler.queue.recovery_contract import (
    build_recovery_duplicate_ignored_transition,
    retry_already_pending,
)


def resolve_existing_retry_decision(
    *,
    job_records: MutableMapping[int, dict[str, object]],
    failed: MutableSet[int],
    terminal: MutableSet[int],
    job_id: int,
    reason: object,
    record: object,
    pid: object = None,
) -> InMemoryRetryDecision | None:
    if job_id in terminal:
        evidence = retry_terminal_already_evidence(
            job_id=job_id,
            reason=reason,
            record=job_records.get(job_id),
        )
        return InMemoryRetryDecision(False, 0, (dict(evidence),))
    if not isinstance(record, Mapping):
        evidence = retry_missing_record_evidence(job_id=job_id, reason=reason, record=record)
        failed.add(job_id)
        terminal.add(job_id)
        return InMemoryRetryDecision(False, 1, (dict(evidence),))
    if retry_already_pending(record):
        duplicate_transition = build_recovery_duplicate_ignored_transition(record, reason, pid=pid)
        updated_record = duplicate_transition.as_record()
        updated = updated_record if type(updated_record) is dict else dict(record)
        job_records[job_id] = updated
        duplicate_evidence = retry_duplicate_pending_evidence(
            job_id=job_id,
            reason=reason,
            generation=dict.get(updated, "attempt", 0),
        )
        return InMemoryRetryDecision(False, 0, (dict(duplicate_evidence),))
    return None


__all__ = ("resolve_existing_retry_decision",)
