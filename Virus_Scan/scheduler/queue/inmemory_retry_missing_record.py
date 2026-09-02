"""Evidence producers for retry requests with unavailable job records."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_text,
)
from Virus_Scan.scheduler.queue.inmemory_retry_missing_contract import (
    InMemoryRetryDuplicatePendingEvidence,
    InMemoryRetryMissingRecordEvidence,
    InMemoryRetryTerminalAlreadyEvidence,
    _retry_int,
)


def retry_duplicate_pending_evidence(
    *,
    job_id: int,
    reason: object,
    generation: object,
) -> Mapping[str, object]:
    normalized_job_id = _retry_int(job_id, field_name="job_id")
    normalized_generation = _retry_int(
        generation,
        field_name="generation",
    )
    return InMemoryRetryDuplicatePendingEvidence(
        job_id=normalized_job_id,
        generation=normalized_generation,
        reason=scheduler_evidence_text(
            reason,
            missing_text="retry_duplicate_pending",
            field_name="retry_reason",
        ),
        detail=(
            "retry recovery ignored duplicate pending retry for job "
            + int.__str__(normalized_job_id)
            + " generation "
            + int.__str__(normalized_generation)
        ),
    ).as_record()


def retry_terminal_already_evidence(
    *,
    job_id: int,
    reason: object,
    record: object = None,
) -> Mapping[str, object]:
    normalized_job_id = _retry_int(job_id, field_name="job_id")
    generation = 0
    record_items = no_hook_mapping_items(record)
    if record_items is not None:
        generation = _retry_int(
            dict.get(dict(record_items), "attempt", 0),
            field_name="generation",
        )
    return InMemoryRetryTerminalAlreadyEvidence(
        job_id=normalized_job_id,
        generation=generation,
        reason=scheduler_evidence_text(
            reason,
            missing_text="retry_terminal_already",
            field_name="retry_reason",
        ),
        detail=(
            "retry recovery was requested for terminal job "
            + int.__str__(normalized_job_id)
            + " generation "
            + int.__str__(generation)
        ),
    ).as_record()


def retry_missing_record_evidence(
    *,
    job_id: int,
    reason: object,
    record: object,
) -> Mapping[str, object]:
    normalized_job_id = _retry_int(job_id, field_name="job_id")
    if record is None:
        category = "KeyError"
        detail = (
            "job record "
            + int.__str__(normalized_job_id)
            + " is missing during retry recovery"
        )
    else:
        category = "TypeError"
        detail = (
            "job record must be a mapping, got "
            + no_hook_type_name(record)
        )
    return InMemoryRetryMissingRecordEvidence(
        job_id=normalized_job_id,
        reason=scheduler_evidence_text(
            reason,
            missing_text="retry_missing_record",
            field_name="retry_reason",
        ),
        error_category=category,
        error_source="inmemory_retry_recovery.job_records",
        detail=detail,
    ).as_record()


__all__ = (
    "InMemoryRetryDuplicatePendingEvidence",
    "InMemoryRetryMissingRecordEvidence",
    "InMemoryRetryTerminalAlreadyEvidence",
    "retry_duplicate_pending_evidence",
    "retry_missing_record_evidence",
    "retry_terminal_already_evidence",
)
