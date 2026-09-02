"""Bounded retry-recovery preparation steps for in-memory queue jobs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableMapping, MutableSet

from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    InMemoryRetryDecision,
    safe_retry_int as _safe_retry_int,
)
from Virus_Scan.scheduler.queue.inmemory_retry_publication import publish_cancel_payload
from Virus_Scan.scheduler.queue.inmemory_retry_recovery_support import resolve_existing_retry_decision
from Virus_Scan.scheduler.queue.recovery_history_transition import (
    RecoveryHistoryTransitionRequest,
    build_recovery_history_transition,
)


@dataclass(frozen=True, slots=True)
class RetryRecoveryContext:
    record: Mapping[str, object]
    path: object
    old_generation: int
    max_job_retries_int: int
    cancel_publication: object
    cancel_publication_evidence_records: tuple[dict[str, object], ...]


def publish_retry_cancel_transition(
    *,
    job_records: MutableMapping[int, dict[str, object]],
    job_id: int,
    rec: Mapping[str, object],
    reason: object,
    old_generation: int,
    cancel_table: object,
    cancel_generation: object,
    cancel_flags: object,
    pid: object = None,
) -> tuple[Mapping[str, object], object, tuple[dict[str, object], ...]]:
    """Publish cancel state and attach failure evidence to retry history."""
    cancel_publication = publish_cancel_payload(
        job_id=job_id,
        reason=reason,
        generation=old_generation,
        cancel_table=cancel_table,
        cancel_generation=cancel_generation,
        cancel_flags=cancel_flags,
    )
    evidence_records: list[dict[str, object]] = []
    if cancel_publication.evidence is not None:
        transition = build_recovery_history_transition(
            RecoveryHistoryTransitionRequest(
                record=rec,
                reason="retry_cancel_publication_failed",
                pid=pid,
                attempt=old_generation,
                action="retry_cancel_publication_failed",
                extra=cancel_publication.as_history_extra(),
            )
        )
        rec = transition.as_record()
        if type(rec) is dict:
            job_records[job_id] = rec
        evidence_records.append(dict(cancel_publication.evidence.as_record()))
    return rec, cancel_publication, tuple(evidence_records)


def prepare_retry_recovery_context(
    *,
    job_records: MutableMapping[int, dict[str, object]],
    active: MutableMapping[int, object],
    failed: MutableSet[int],
    terminal: MutableSet[int],
    job_id: int,
    reason: object,
    max_job_retries: int,
    cancel_table: object,
    cancel_generation: object,
    cancel_flags: object,
    pid: object = None,
) -> InMemoryRetryDecision | RetryRecoveryContext:
    """Normalize retry state or return an existing terminal decision."""
    rec = job_records.get(job_id)
    existing_decision = resolve_existing_retry_decision(
        job_records=job_records,
        failed=failed,
        terminal=terminal,
        job_id=job_id,
        reason=reason,
        record=rec,
        pid=pid,
    )
    if existing_decision is not None:
        return existing_decision
    assert isinstance(rec, Mapping)
    path = rec.get("file")
    old_generation, rec = _safe_retry_int(
        value=rec.get("attempt", 0) or 0,
        replacement_value=0,
        job_id=job_id,
        generation=0,
        reason=reason,
        field="attempt",
        record=rec,
    )
    max_retry_int, rec = _safe_retry_int(
        value=max_job_retries or 0,
        replacement_value=0,
        job_id=job_id,
        generation=old_generation,
        reason=reason,
        field="max_job_retries",
        record=rec,
    )
    job_records[job_id] = rec
    active.pop(job_id, None)
    rec, cancel_publication, evidence_records = publish_retry_cancel_transition(
        job_records=job_records,
        job_id=job_id,
        rec=rec,
        reason=reason,
        old_generation=old_generation,
        cancel_table=cancel_table,
        cancel_generation=cancel_generation,
        cancel_flags=cancel_flags,
        pid=pid,
    )
    return RetryRecoveryContext(
        rec,
        path,
        old_generation,
        max_retry_int,
        cancel_publication,
        evidence_records,
    )


__all__ = (
    "RetryRecoveryContext",
    "prepare_retry_recovery_context",
    "publish_retry_cancel_transition",
)
