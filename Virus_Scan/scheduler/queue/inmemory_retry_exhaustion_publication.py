"""Retry-exhaustion result-publication failure handling owned by queue retry."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import MutableMapping, MutableSet

from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import terminal_transition_decision as _im_terminal_transition_decision
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    INMEMORY_RETRY_RECOVERY_EXCEPTIONS,
    InMemoryRetryDecision,
    retry_suppression_record_failure_error,
)
from Virus_Scan.scheduler.queue.inmemory_retry_publication import (
    record_retry_result_publication_failure,
    retry_result_publication_evidence,
)


@dataclass(frozen=True, slots=True)
class RetryExhaustedPublicationFailureRequest:
    job_records: MutableMapping[int, dict[str, object]]
    failed: MutableSet[int]
    terminal: MutableSet[int]
    job_id: int
    reason: object
    path: object
    record: dict[str, object]
    old_generation: int
    publication_error: BaseException
    final_decision_evidence: list[dict[str, object]]


def retry_result_publication_failed(request: RetryExhaustedPublicationFailureRequest) -> InMemoryRetryDecision:
    """Record failed final result publication without hiding retry exhaustion."""
    publication_error = request.publication_error
    try:
        record_scheduler_suppressed("suppressed_exception", publication_error)
    except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as record_exc:
        publication_error = retry_suppression_record_failure_error(publication_error, record_exc)
    publication_evidence = retry_result_publication_evidence(
        job_id=request.job_id,
        generation=request.old_generation,
        reason=request.reason,
        path=request.path,
        error=publication_error,
    )
    record = record_retry_result_publication_failure(record=request.record, evidence=publication_evidence)
    request.job_records[request.job_id] = record
    request.failed.add(request.job_id)
    request.terminal.add(request.job_id)
    _im_terminal_transition_decision(
        record,
        state="failed",
        attempt=request.old_generation,
        now=time.time(),
    )
    publication_evidence_record = dict(publication_evidence.as_record())
    return InMemoryRetryDecision(
        retried=False,
        completed_delta=1,
        evidence=tuple([*request.final_decision_evidence, publication_evidence_record]),
    )
