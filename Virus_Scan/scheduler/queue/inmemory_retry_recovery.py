"""Canonical in-memory retry and cancellation recovery ownership."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import LifecycleRequestRecorder

from typing import Callable, MutableMapping, MutableSet, TYPE_CHECKING

from Virus_Scan.scheduler.queue.inmemory_retry_failure_result import build_worker_error_result
from Virus_Scan.scheduler.queue.inmemory_retry_publication import publish_cancel_payload
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    InMemoryRetryDecision,
    safe_retry_int as _safe_retry_int,
)
from Virus_Scan.scheduler.queue.inmemory_retry_recovery_exhausted import RetryExhaustedRequest, publish_retry_exhausted
from Virus_Scan.scheduler.queue.inmemory_retry_recovery_requeue import publish_retry_pending
from Virus_Scan.scheduler.queue.recovery_history_transition import (
    RecoveryHistoryTransitionRequest,
    build_recovery_history_transition,
)
from Virus_Scan.scheduler.queue.inmemory_retry_recovery_steps import (
    RetryRecoveryContext,
    prepare_retry_recovery_context,
    publish_retry_cancel_transition as _publish_retry_cancel_transition,
)

if TYPE_CHECKING:
    from collections import deque

_WORKER_ERROR_RESULT_BOUNDARY = build_worker_error_result
# Phase 10 facade preserves injected worker result boundary; branch helpers call build_worker_error_result( with caller-supplied worker_error_result.


def replace_with_history_transition(
    *,
    job_records: MutableMapping[int, dict[str, object]],
    job_id: int,
    record: MutableMapping[str, object],
    reason: object,
    pid: object = None,
    now: float | None = None,
    action: str = "history",
    extra: object = None,
) -> dict[str, object]:
    attempt, normalized_record = _safe_retry_int(
        value=(record or {}).get("attempt", 0) if isinstance(record, MutableMapping) else 0,
        replacement_value=0,
        job_id=job_id,
        generation=0,
        reason=reason,
        field="attempt",
        record=record,
    )
    transition = build_recovery_history_transition(
        RecoveryHistoryTransitionRequest(
            record=normalized_record,
            reason=reason,
            pid=pid,
            attempt=attempt,
            now=now,
            action=action,
            extra=extra,
        )
    )
    updated = transition.as_record()
    job_records[job_id] = updated
    return updated



def retry_or_fail(
    *,
    job_records: MutableMapping[int, dict[str, object]],
    active: MutableMapping[int, object],
    pending: deque[tuple[int, object, int]],
    results: MutableMapping[object, object],
    failed: MutableSet[int],
    terminal: MutableSet[int],
    job_id: int,
    reason: object,
    max_job_retries: int,
    cancel_table: object,
    cancel_generation: object,
    cancel_flags: object,
    lifecycle_recorder: LifecycleRequestRecorder,
    worker_error_result: Callable[[object, BaseException | str], dict[str, object]],
    pid: object = None,
) -> InMemoryRetryDecision:
    context = prepare_retry_recovery_context(
        job_records=job_records,
        active=active,
        failed=failed,
        terminal=terminal,
        job_id=job_id,
        reason=reason,
        max_job_retries=max_job_retries,
        cancel_table=cancel_table,
        cancel_generation=cancel_generation,
        cancel_flags=cancel_flags,
        pid=pid,
    )
    if not isinstance(context, RetryRecoveryContext):
        return context
    if context.old_generation < context.max_job_retries_int:
        return publish_retry_pending(
            job_records=job_records,
            pending=pending,
            results=results,
            failed=failed,
            terminal=terminal,
            job_id=job_id,
            reason=reason,
            path=context.path,
            rec=context.record,
            old_generation=context.old_generation,
            max_job_retries_int=context.max_job_retries_int,
            pid=pid,
            cancel_publication_evidence_records=list(context.cancel_publication_evidence_records),
            lifecycle_recorder=lifecycle_recorder,
            worker_error_result=worker_error_result,
        )
    return publish_retry_exhausted(
        RetryExhaustedRequest(
            job_records=job_records,
            results=results,
            failed=failed,
            terminal=terminal,
            job_id=job_id,
            reason=reason,
            path=context.path,
            record=context.record,
            old_generation=context.old_generation,
            pid=pid,
            cancel_publication=context.cancel_publication,
            cancel_publication_evidence_records=list(context.cancel_publication_evidence_records),
            lifecycle_recorder=lifecycle_recorder,
            worker_error_result=worker_error_result,
        )
    )


__all__ = (
    "publish_cancel_payload",
    "replace_with_history_transition",
    "retry_or_fail",
    "_publish_retry_cancel_transition",
)
