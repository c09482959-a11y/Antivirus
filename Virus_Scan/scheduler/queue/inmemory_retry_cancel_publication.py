"""Validated cancel-slot publication for in-memory retry recovery."""
from __future__ import annotations



from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.internal.owned_indexed_sequence import (
    is_owned_indexed_sequence,
    owned_indexed_length,
    owned_indexed_set,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_text,
    scheduler_exception_text,
)
from Virus_Scan.scheduler.queue.inmemory_retry_cancel_evidence import (
    InMemoryCancelPublicationEvidence,
    InMemoryCancelPublicationResult,
)
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    INMEMORY_RETRY_RECOVERY_EXCEPTIONS,
)
from Virus_Scan.scheduler.queue.recovery_contract import cancel_payload
from Virus_Scan.scheduler.queue.retry_evidence_support import (
    retry_evidence_int,
)


def _cancel_failure(
    *,
    job_id: int,
    generation: int,
    reason: object,
    flags: int | None,
    error: BaseException,
) -> InMemoryCancelPublicationResult:
    evidence = InMemoryCancelPublicationEvidence(
        job_id=job_id,
        generation=generation,
        reason=scheduler_evidence_text(
            reason,
            missing_text="recovery",
            field_name="retry_reason",
        ),
        flags=flags,
        error_category="cancel_publication_failed",
        error_source="inmemory_retry_recovery.publish_cancel_payload",
        detail=scheduler_exception_text(error),
    )
    return InMemoryCancelPublicationResult(published=False, evidence=evidence)


def publish_cancel_payload(
    *,
    job_id: int,
    reason: object,
    generation: int,
    cancel_table: object,
    cancel_generation: object,
    cancel_flags: object,
    flags: int | None = None,
) -> InMemoryCancelPublicationResult:
    try:
        normalized_job_id = retry_evidence_int(job_id, field_name="job_id")
        normalized_generation = retry_evidence_int(
            generation,
            field_name="generation",
        )
        normalized_flags = (
            None
            if flags is None
            else retry_evidence_int(flags, field_name="flags")
        )
    except ValueError as exc:
        return _cancel_failure(
            job_id=0,
            generation=0,
            reason=reason,
            flags=None,
            error=exc,
        )
    payload = cancel_payload(reason, normalized_generation)
    if normalized_flags is not None:
        payload["flags"] = normalized_flags
    payload_flags = retry_evidence_int(
        dict.get(payload, "flags"),
        field_name="flags",
    )
    try:
        if cancel_generation is not None and cancel_flags is not None:
            if (
                not is_owned_indexed_sequence(cancel_generation, writable=True)
                or not is_owned_indexed_sequence(cancel_flags, writable=True)
            ):
                raise ValueError("cancel_shared_arrays_rejected")
            if (
                normalized_job_id >= owned_indexed_length(cancel_generation)
                or normalized_job_id >= owned_indexed_length(cancel_flags)
            ):
                raise ValueError("cancel_job_id_out_of_range")
            owned_indexed_set(cancel_generation, normalized_job_id, normalized_generation)
            owned_indexed_set(cancel_flags, normalized_job_id, payload_flags)
        elif cancel_generation is not None or cancel_flags is not None:
            raise ValueError("cancel_shared_array_pair_incomplete")
        elif cancel_table is not None:
            if type(cancel_table) is not dict:
                raise ValueError("cancel_table_rejected")
            dict.__setitem__(
                cancel_table,
                int.__str__(normalized_job_id),
                payload,
            )
        return InMemoryCancelPublicationResult(published=True, evidence=None)
    except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as exc:
        try:
            record_scheduler_suppressed("suppressed_exception", exc)
        except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as record_exc:
            exc = RuntimeError(
                scheduler_exception_text(exc)
                + "; suppression_record_failed="
                + scheduler_exception_text(record_exc)
            )
        return _cancel_failure(
            job_id=normalized_job_id,
            generation=normalized_generation,
            reason=reason,
            flags=payload_flags,
            error=exc,
        )


__all__ = ("publish_cancel_payload",)
