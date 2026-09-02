"""Retry exhaustion finalization branch for in-memory scheduler recovery."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import LifecycleRequestRecorder

from dataclasses import dataclass
from typing import Callable, MutableMapping, MutableSet

from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    InMemoryRetryDecision,
    safe_retry_history,
)
from Virus_Scan.scheduler.queue.inmemory_retry_exhaustion_integrity import attach_retry_exhaustion_integrity
from Virus_Scan.scheduler.queue.inmemory_retry_exhaustion_lifecycle import (
    RetryExhaustedLifecycleFailureRequest,
    record_failed_lifecycle_evidence,
)
from Virus_Scan.scheduler.queue.inmemory_retry_exhaustion_publication import (
    RetryExhaustedPublicationFailureRequest,
    retry_result_publication_failed,
)
from Virus_Scan.scheduler.queue.inmemory_retry_recovery_exhausted_steps import (
    attach_retry_exhaustion_integrity_if_mapping,
    build_retry_exhausted_worker_result,
    publish_retry_exhausted_result,
    record_retry_exhausted_terminal_state,
)


@dataclass(frozen=True, slots=True)
class RetryExhaustedRequest:
    job_records: MutableMapping[int, dict[str, object]]
    results: MutableMapping[object, object]
    failed: MutableSet[int]
    terminal: MutableSet[int]
    job_id: int
    reason: object
    path: object
    record: dict[str, object]
    old_generation: int
    pid: object
    cancel_publication: object
    cancel_publication_evidence_records: list[dict[str, object]]
    lifecycle_recorder: LifecycleRequestRecorder
    worker_error_result: Callable[[object, BaseException | str], dict[str, object]]


def publish_retry_exhausted(request: RetryExhaustedRequest) -> InMemoryRetryDecision:
    retry_history = safe_retry_history(
        record=request.record,
        job_id=request.job_id,
        generation=request.old_generation,
        reason=request.reason,
    )
    request.job_records[request.job_id] = request.record
    failure_result = build_retry_exhausted_worker_result(
        worker_error_result=request.worker_error_result,
        path=request.path,
        reason=request.reason,
        retry_history=retry_history,
        job_id=request.job_id,
        old_generation=request.old_generation,
    )
    result = failure_result.result_dict()
    final_decision_evidence: list[dict[str, object]] = list(request.cancel_publication_evidence_records)
    if failure_result.evidence is not None:
        final_decision_evidence.append(failure_result.evidence_dict() or {})
    attach_retry_exhaustion_integrity_if_mapping(
        attach_retry_exhaustion_integrity=attach_retry_exhaustion_integrity,
        res=result,
        rec=request.record,
        job_records=request.job_records,
        job_id=request.job_id,
        reason=request.reason,
        old_generation=request.old_generation,
        pid=request.pid,
        cancel_publication=request.cancel_publication,
    )
    publication_error = publish_retry_exhausted_result(
        results=request.results,
        path=request.path,
        res=result,
    )
    if publication_error is not None:
        return retry_result_publication_failed(
            RetryExhaustedPublicationFailureRequest(
                job_records=request.job_records,
                failed=request.failed,
                terminal=request.terminal,
                job_id=request.job_id,
                reason=request.reason,
                path=request.path,
                record=request.record,
                old_generation=request.old_generation,
                publication_error=publication_error,
                final_decision_evidence=final_decision_evidence,
            )
        )
    lifecycle_error = record_retry_exhausted_terminal_state(
        failed=request.failed,
        terminal=request.terminal,
        job_id=request.job_id,
        rec=request.record,
        old_generation=request.old_generation,
        lifecycle_recorder=request.lifecycle_recorder,
        reason=request.reason,
        pid=request.pid,
    )
    if lifecycle_error is not None:
        record_failed_lifecycle_evidence(
            RetryExhaustedLifecycleFailureRequest(
                job_records=request.job_records,
                results=request.results,
                job_id=request.job_id,
                reason=request.reason,
                path=request.path,
                record=request.record,
                result=result,
                old_generation=request.old_generation,
                lifecycle_error=lifecycle_error,
                final_decision_evidence=final_decision_evidence,
            )
        )
    return InMemoryRetryDecision(
        retried=False,
        completed_delta=1,
        evidence=tuple(final_decision_evidence),
    )
