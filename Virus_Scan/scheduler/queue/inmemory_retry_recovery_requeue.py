"""Retry requeue publication branch for in-memory scheduler recovery."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest, LifecycleRequestRecorder

import logging
import os
import time

from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import terminal_transition_decision as _im_terminal_transition_decision
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    INMEMORY_RETRY_RECOVERY_EXCEPTIONS,
    InMemoryRetryDecision,
    retry_suppression_record_failure_error,
)
from Virus_Scan.scheduler.queue.inmemory_retry_failure_result import build_worker_error_result
from Virus_Scan.scheduler.queue.inmemory_retry_publication import (
    record_retry_lifecycle_failure,
    record_retry_pending_publication_failure,
    record_retry_result_publication_failure,
    retry_lifecycle_evidence,
    retry_pending_publication_evidence,
    retry_result_publication_evidence,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path, scheduler_evidence_text
from Virus_Scan.scheduler.queue.recovery_contract import build_inmemory_retry_transition
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.queue.inmemory_retry_requeue_contracts import (
        RetryEvidenceRecords,
        RetryJobRecord,
        RetryJobRecords,
        RetryLifecycleRecorder,
        RetryPendingQueue,
        RetryResults,
        RetryTerminalSet,
        RetryWorkerErrorResult,
    )


def publish_retry_pending(
    *,
    job_records: RetryJobRecords,
    pending: RetryPendingQueue,
    results: RetryResults,
    failed: RetryTerminalSet,
    terminal: RetryTerminalSet,
    job_id: int,
    reason: object,
    path: object,
    rec: RetryJobRecord,
    old_generation: int,
    max_job_retries_int: int,
    pid: object,
    cancel_publication_evidence_records: RetryEvidenceRecords,
    lifecycle_recorder: RetryLifecycleRecorder,
    worker_error_result: RetryWorkerErrorResult,
) -> InMemoryRetryDecision:
    del old_generation  # Explicitly unused contract parameters.
    retry_transition = build_inmemory_retry_transition(rec, reason, pid=pid)
    new_generation = retry_transition.new_generation
    rec = retry_transition.as_record()
    job_records[job_id] = rec
    retry_success_evidence: RetryEvidenceRecords = list(cancel_publication_evidence_records)
    try:
        lifecycle_recorder(
            InMemoryLifecycleRecordRequest(
                job_id=job_id,
                attempt=int(new_generation),
                transition="retry_pending",
                worker_pid=pid,
                reason=reason,
                state="pending_retry",
            )
        )
    except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as lifecycle_exc:
        try:
            record_scheduler_suppressed("suppressed_exception", lifecycle_exc)
        except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as record_exc:
            lifecycle_exc = retry_suppression_record_failure_error(lifecycle_exc, record_exc)
        lifecycle_evidence = retry_lifecycle_evidence(
            job_id=job_id,
            generation=int(new_generation),
            reason=reason,
            lifecycle_state="retry_pending",
            error=lifecycle_exc,
        )
        rec = record_retry_lifecycle_failure(record=rec, evidence=lifecycle_evidence)
        job_records[job_id] = rec
        retry_success_evidence.append(dict(lifecycle_evidence.as_record()))
    try:
        pending.appendleft((job_id, path, int(new_generation)))
    except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as pending_exc:
        try:
            record_scheduler_suppressed("suppressed_exception", pending_exc)
        except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as record_exc:
            pending_exc = retry_suppression_record_failure_error(pending_exc, record_exc)
        pending_evidence = retry_pending_publication_evidence(
            job_id=job_id,
            generation=int(new_generation),
            reason=reason,
            path=path,
            error=pending_exc,
        )
        rec = record_retry_pending_publication_failure(record=rec, evidence=pending_evidence)
        rec["state"] = "failed"
        job_records[job_id] = rec
        reason_text = scheduler_evidence_text(
            reason,
            missing_text="retry_pending_publication",
            field_name="retry_reason",
        )
        err = RuntimeError("in-memory scheduler retry pending publication failed: " + reason_text)
        failure_result = build_worker_error_result(
            worker_error_result=worker_error_result,
            path=path,
            error=err,
            job_id=job_id,
            generation=int(new_generation),
            reason=reason,
        )
        result_record = failure_result.result_dict()
        res = result_record if type(result_record) is dict else {}
        integrity = dict(dict.get(res, "scan_integrity") or {})
        integrity.update(pending_evidence.as_scan_integrity())
        res["retry_pending_publication_failed"] = True
        res["retry_pending_publication_evidence"] = dict(pending_evidence.as_record())
        res["scan_integrity"] = integrity
        evidence_records: RetryEvidenceRecords = [dict(pending_evidence.as_record())]
        if failure_result.evidence is not None:
            evidence_records.append(failure_result.evidence_dict() or {})
        try:
            results[path] = res
        except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as result_publish_exc:
            publication_evidence = retry_result_publication_evidence(
                job_id=job_id,
                generation=int(new_generation),
                reason=reason,
                path=path,
                error=result_publish_exc,
            )
            rec = record_retry_result_publication_failure(record=rec, evidence=publication_evidence)
            job_records[job_id] = rec
            evidence_records.append(dict(publication_evidence.as_record()))
        failed.add(job_id)
        terminal.add(job_id)
        _im_terminal_transition_decision(rec, state="failed", attempt=int(new_generation), now=time.time())
        return InMemoryRetryDecision(retried=False, completed_delta=1, evidence=tuple(evidence_records))
    if int(new_generation) >= max_job_retries_int:
        logging.warning(
            "in-memory scheduler final retry job_id=%s attempt=%s/%s reason=%s file=%s",
            job_id,
            rec["attempt"],
            max_job_retries_int,
            reason,
            os.path.basename(scheduler_evidence_path(path, field_name="retry_path")),
        )
    return InMemoryRetryDecision(retried=True, completed_delta=0, evidence=tuple(retry_success_evidence))
