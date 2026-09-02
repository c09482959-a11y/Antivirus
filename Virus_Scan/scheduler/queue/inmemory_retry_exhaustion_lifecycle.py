"""Retry-exhaustion lifecycle-publication failure handling owned by queue retry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import MutableMapping

from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    INMEMORY_RETRY_RECOVERY_EXCEPTIONS,
    retry_suppression_record_failure_error,
)
from Virus_Scan.scheduler.queue.inmemory_retry_publication import (
    record_retry_lifecycle_failure,
    record_retry_result_publication_failure,
    retry_lifecycle_evidence,
    retry_result_publication_evidence,
)


@dataclass(frozen=True, slots=True)
class RetryExhaustedLifecycleFailureRequest:
    job_records: MutableMapping[int, dict[str, object]]
    results: MutableMapping[object, object]
    job_id: int
    reason: object
    path: object
    record: dict[str, object]
    result: object
    old_generation: int
    lifecycle_error: BaseException
    final_decision_evidence: list[dict[str, object]]


def record_failed_lifecycle_evidence(request: RetryExhaustedLifecycleFailureRequest) -> None:
    """Record lifecycle-recorder failures against an exhausted retry result."""
    lifecycle_error = request.lifecycle_error
    try:
        record_scheduler_suppressed("suppressed_exception", lifecycle_error)
    except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as record_exc:
        lifecycle_error = retry_suppression_record_failure_error(lifecycle_error, record_exc)
    lifecycle_evidence = retry_lifecycle_evidence(
        job_id=request.job_id,
        generation=request.old_generation,
        reason=request.reason,
        lifecycle_state="failed",
        error=lifecycle_error,
    )
    request.final_decision_evidence.append(dict(lifecycle_evidence.as_record()))
    record = record_retry_lifecycle_failure(record=request.record, evidence=lifecycle_evidence)
    request.job_records[request.job_id] = record
    if isinstance(request.result, dict):
        integrity = dict(request.result.get("scan_integrity") or {})
        integrity.update(lifecycle_evidence.as_scan_integrity())
        request.result["retry_lifecycle_publication_failed"] = True
        request.result["retry_lifecycle_publication_evidence"] = dict(lifecycle_evidence.as_record())
        request.result["scan_integrity"] = integrity
        try:
            request.results[request.path] = request.result
        except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as result_publish_exc:
            publication_evidence = retry_result_publication_evidence(
                job_id=request.job_id,
                generation=request.old_generation,
                reason=request.reason,
                path=request.path,
                error=result_publish_exc,
            )
            record = record_retry_result_publication_failure(record=record, evidence=publication_evidence)
            request.job_records[request.job_id] = record
            request.final_decision_evidence.append(dict(publication_evidence.as_record()))
