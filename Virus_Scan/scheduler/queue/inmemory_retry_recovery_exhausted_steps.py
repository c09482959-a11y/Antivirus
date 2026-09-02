"""Bounded helper steps for retry exhaustion publication."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest, LifecycleRequestRecorder

import time
from typing import Callable, MutableMapping, MutableSet

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import terminal_transition_decision as _im_terminal_transition_decision
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import INMEMORY_RETRY_RECOVERY_EXCEPTIONS
from Virus_Scan.scheduler.queue.inmemory_retry_failure_result import build_worker_error_result


def retry_exhausted_error(reason: object, retry_history: tuple[object, ...]) -> RuntimeError:
    reason_text = scheduler_evidence_text(reason, missing_text="retry_exhausted", field_name="retry_reason")
    return RuntimeError(
        "in-memory scheduler job failed after retries: "
        + reason_text
        + "; history_count="
        + int.__str__(len(retry_history))
    )


def build_retry_exhausted_worker_result(
    *,
    worker_error_result: Callable[[object, BaseException | str], dict[str, object]],
    path: object,
    reason: object,
    retry_history: tuple[object, ...],
    job_id: int,
    old_generation: int,
) -> object:
    return build_worker_error_result(
        worker_error_result=worker_error_result,
        path=path,
        error=retry_exhausted_error(reason, retry_history),
        job_id=job_id,
        generation=old_generation,
        reason=reason,
    )


def attach_retry_exhaustion_integrity_if_mapping(
    *,
    attach_retry_exhaustion_integrity: Callable[..., object],
    res: object,
    rec: dict[str, object],
    job_records: MutableMapping[int, dict[str, object]],
    job_id: int,
    reason: object,
    old_generation: int,
    pid: object,
    cancel_publication: object,
) -> None:
    if isinstance(res, dict):
        attach_retry_exhaustion_integrity(
            res=res,
            rec=rec,
            job_records=job_records,
            job_id=job_id,
            reason=reason,
            old_generation=old_generation,
            pid=pid,
            cancel_publication=cancel_publication,
        )


def publish_retry_exhausted_result(
    *,
    results: MutableMapping[object, object],
    path: object,
    res: object,
) -> BaseException | None:
    try:
        results[path] = res
    except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as result_publish_exc:
        return result_publish_exc
    return None


def record_retry_exhausted_terminal_state(
    *,
    failed: MutableSet[int],
    terminal: MutableSet[int],
    job_id: int,
    rec: dict[str, object],
    old_generation: int,
    lifecycle_recorder: LifecycleRequestRecorder,
    reason: object,
    pid: object,
) -> BaseException | None:
    failed.add(job_id)
    terminal.add(job_id)
    _im_terminal_transition_decision(rec, state="failed", attempt=old_generation, now=time.time())
    try:
        lifecycle_recorder(
            InMemoryLifecycleRecordRequest(
                job_id=job_id,
                attempt=old_generation,
                transition="failed",
                worker_pid=pid,
                reason=reason,
                state="failed",
            )
        )
    except INMEMORY_RETRY_RECOVERY_EXCEPTIONS as lifecycle_exc:
        return lifecycle_exc
    return None




__all__ = (
    "attach_retry_exhaustion_integrity_if_mapping",
    "build_retry_exhausted_worker_result",
    "publish_retry_exhausted_result",
    "record_retry_exhausted_terminal_state",
)
