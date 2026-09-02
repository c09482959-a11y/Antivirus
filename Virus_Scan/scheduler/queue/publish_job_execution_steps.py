"""Bounded steps for durable process-queue publication execution."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_path_text,
    scheduler_text,
)
from Virus_Scan.scheduler.queue.publish_job_contract import (
    ProcessQueuePublishAttempt,
    ProcessQueuePublishResult,
)
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockReleaseDecision

_PROCESS_QUEUE_PUBLICATION_REQUIRES_EXACT_ATTEMPT = "process queue publication requires exact publish attempt"


def validate_locked_publication_inputs(
    *,
    queue_dir: object,
    pending_dir: object,
    attempt: object,
    identity: str,
) -> tuple[ProcessQueuePublishAttempt, str, str, str]:
    if type(attempt) is not ProcessQueuePublishAttempt:
        raise TypeError(_PROCESS_QUEUE_PUBLICATION_REQUIRES_EXACT_ATTEMPT)
    safe_identity, identity_reason = scheduler_text(
        identity,
        unsupported_reason="process_queue_publish_lock_identity_rejected",
    )
    safe_queue_dir = scheduler_evidence_path(
        queue_dir,
        field_name="process_queue_publish_queue_dir",
    )
    safe_pending_dir, pending_reason = scheduler_path_text(pending_dir)
    if identity_reason or not safe_identity:
        reason = identity_reason or "missing_identity"
        raise ValueError("invalid process queue publication identity:" + reason)
    if pending_reason or not safe_pending_dir:
        reason = pending_reason or "missing_path"
        raise ValueError("invalid process queue pending directory:" + reason)
    return attempt, safe_identity, safe_queue_dir, safe_pending_dir


def run_process_queue_enqueue_guard(
    *,
    queue_dir: object,
    job: object,
    safe_identity: str,
    enqueue_guard: Callable[..., bool],
    record_scheduler_suppressed: Callable[..., object],
    guard_failure_stage: str,
) -> ProcessQueuePublishResult | None:
    try:
        allowed = enqueue_guard(
            queue_dir,
            job,
            identity=safe_identity,
            states=("pending", "active", "done", "failed", "quarantine", "file_results"),
        )
        if type(allowed) is not bool or not allowed:
            return ProcessQueuePublishResult(published=False, guard_blocked=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_scheduler_suppressed(
            guard_failure_stage,
            exc,
            extra={"identity": safe_identity},
        )
        return ProcessQueuePublishResult(published=False, guard_exception=True)
    return None


def write_locked_pending_job(
    *,
    pending_dir: str,
    attempt: ProcessQueuePublishAttempt,
    job: object,
    write_queue_job_json_durable: Callable[..., bool],
) -> ProcessQueuePublishResult | None:
    pending_path = Path(pending_dir)
    tmp = pending_path / (attempt.pending_name + ".tmp")
    final = pending_path / attempt.pending_name
    wrote = write_queue_job_json_durable(
        tmp,
        final,
        job,
        log_context="queue_tmp_to_final",
    )
    if type(wrote) is not bool or not wrote:
        return ProcessQueuePublishResult(published=False, durable_write_failed=True)
    return None


def note_identity_index(
    *,
    queue_dir: object,
    safe_identity: str,
    identity_index_note: Callable[..., object],
    record_scheduler_suppressed: Callable[..., object],
    identity_index_failure_stage: str,
) -> bool:
    try:
        identity_index_note(queue_dir, safe_identity)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_scheduler_suppressed(
            identity_index_failure_stage,
            exc,
            extra={"identity": safe_identity},
        )
        return True
    return False


def apply_publication_state_delta(
    *,
    queue_dir: object,
    safe_queue_dir: str,
    safe_identity: str,
    state_delta: Callable[..., object] | None,
    record_scheduler_suppressed: Callable[..., object],
) -> None:
    if state_delta is None:
        return
    try:
        state_delta(queue_dir, file_pending=1)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_scheduler_suppressed(
            "process_queue_state_delta_failed",
            exc,
            extra={"queue_dir": safe_queue_dir, "identity": safe_identity},
        )


def release_process_queue_identity_lock(
    *,
    lock: object,
    safe_identity: str,
    release_identity_lock_decision: Callable[[object], IdentityLockReleaseDecision],
    record_scheduler_suppressed: Callable[..., object],
    release_failure_stage: str,
) -> bool:
    decision = release_identity_lock_decision(lock)
    if type(decision) is not IdentityLockReleaseDecision or not decision.released:
        reason = (
            decision.reason
            if type(decision) is IdentityLockReleaseDecision
            else "process_queue_identity_lock_release_decision_invalid"
        )
        record_scheduler_suppressed(
            release_failure_stage,
            RuntimeError(reason),
            extra={"identity": safe_identity, "release_reason": reason},
        )
        return False
    return True


__all__ = (
    "apply_publication_state_delta",
    "note_identity_index",
    "release_process_queue_identity_lock",
    "run_process_queue_enqueue_guard",
    "validate_locked_publication_inputs",
    "write_locked_pending_job",
)
