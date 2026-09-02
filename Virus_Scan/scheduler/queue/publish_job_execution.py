"""Durable execution for one validated process-queue publication."""
from __future__ import annotations

from typing import Callable
from dataclasses import replace

from Virus_Scan.scheduler.queue.publish_job_contract import (
    ProcessQueuePublishAttempt,
    ProcessQueuePublishResult,
)
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockReleaseDecision
from Virus_Scan.scheduler.queue.publish_job_execution_steps import (
    apply_publication_state_delta,
    note_identity_index,
    release_process_queue_identity_lock,
    run_process_queue_enqueue_guard,
    validate_locked_publication_inputs,
    write_locked_pending_job,
)


def publish_locked_process_queue_job(
    *,
    queue_dir: object,
    pending_dir: object,
    attempt: ProcessQueuePublishAttempt,
    identity: str,
    lock: object,
    enqueue_guard: Callable[..., bool],
    write_queue_job_json_durable: Callable[..., bool],
    identity_index_note: Callable[..., object],
    release_identity_lock_decision: Callable[[object], IdentityLockReleaseDecision],
    record_scheduler_suppressed: Callable[..., object],
    guard_failure_stage: str,
    identity_index_failure_stage: str,
    release_failure_stage: str,
    state_delta: Callable[..., object] | None = None,
) -> ProcessQueuePublishResult:
    """Publish one already-locked pending job through queue-owned dependencies."""
    valid_attempt, safe_identity, safe_queue_dir, safe_pending_dir = validate_locked_publication_inputs(
        queue_dir=queue_dir,
        pending_dir=pending_dir,
        attempt=attempt,
        identity=identity,
    )
    job = valid_attempt.job
    publication_result: ProcessQueuePublishResult | None = None
    release_succeeded = False
    try:
        guard_result = run_process_queue_enqueue_guard(
            queue_dir=queue_dir,
            job=job,
            safe_identity=safe_identity,
            enqueue_guard=enqueue_guard,
            record_scheduler_suppressed=record_scheduler_suppressed,
            guard_failure_stage=guard_failure_stage,
        )
        if guard_result is not None:
            publication_result = guard_result
        else:
            write_result = write_locked_pending_job(
                pending_dir=safe_pending_dir,
                attempt=valid_attempt,
                job=job,
                write_queue_job_json_durable=write_queue_job_json_durable,
            )
            if write_result is not None:
                publication_result = write_result
            else:
                identity_index_failed = note_identity_index(
                    queue_dir=queue_dir,
                    safe_identity=safe_identity,
                    identity_index_note=identity_index_note,
                    record_scheduler_suppressed=record_scheduler_suppressed,
                    identity_index_failure_stage=identity_index_failure_stage,
                )
                apply_publication_state_delta(
                    queue_dir=queue_dir,
                    safe_queue_dir=safe_queue_dir,
                    safe_identity=safe_identity,
                    state_delta=state_delta,
                    record_scheduler_suppressed=record_scheduler_suppressed,
                )
                publication_result = ProcessQueuePublishResult(
                    published=True,
                    identity_index_failed=identity_index_failed,
                )
    finally:
        release_succeeded = release_process_queue_identity_lock(
            lock=lock,
            safe_identity=safe_identity,
            release_identity_lock_decision=release_identity_lock_decision,
            record_scheduler_suppressed=record_scheduler_suppressed,
            release_failure_stage=release_failure_stage,
        )
    if publication_result is None:
        raise RuntimeError("process_queue_publication_result_missing")
    return publication_result if release_succeeded else replace(publication_result, release_failed=True)


__all__ = ("publish_locked_process_queue_job",)
