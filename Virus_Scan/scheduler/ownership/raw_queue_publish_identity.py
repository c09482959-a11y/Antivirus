"""Typed identity-lock decisions for raw queue publication."""
from __future__ import annotations

from Virus_Scan.scheduler.ownership.raw_queue_publish_result import (
    RawQueuePublishRequest,
    RawQueuePublishResult,
    raw_queue_publish_result,
    record_raw_queue_publish_failure,
)
from Virus_Scan.scheduler.queue.identity_lock import (
    IdentityLockAcquireDecision,
    IdentityLockReleaseDecision,
)


def _identity_rejection(
    deps: object,
    reason: str,
    *,
    file_id: str,
    seq: int,
    attempt: int,
    collector: str,
    record_failure: bool,
) -> RawQueuePublishResult:
    if record_failure:
        record_raw_queue_publish_failure(deps, reason)
    return raw_queue_publish_result(
        RawQueuePublishRequest(
            published=False,
            reason=reason,
            file_id=file_id,
            seq=seq,
            attempt=attempt,
            collector=collector,
        )
    )


def acquire_raw_queue_identity_lock(
    queue_dir: object,
    identity: str,
    deps: object,
    *,
    file_id: str,
    seq: int,
    attempt: int,
    collector: str,
) -> tuple[object | None, RawQueuePublishResult | None]:
    """Acquire and validate the canonical typed raw-queue identity lock."""
    decision = deps.acquire_identity_lock_decision(queue_dir, identity)
    reason = ""
    record_failure = True
    if type(decision) is not IdentityLockAcquireDecision:
        reason = "raw_publish_identity_lock_decision_rejected"
    elif not decision.acquired:
        if decision.reason == "process_queue_identity_lock_already_locked":
            reason = "raw_publish_identity_lock_already_locked"
            record_failure = False
        else:
            reason = "raw_publish_identity_lock_failed_closed"
    elif decision.lock_path is None:
        reason = "raw_publish_identity_lock_decision_rejected"
    else:
        return decision.lock_path, None
    return None, _identity_rejection(
        deps,
        reason,
        file_id=file_id,
        seq=seq,
        attempt=attempt,
        collector=collector,
        record_failure=record_failure,
    )


def release_raw_queue_identity_lock(lock: object, deps: object) -> bool:
    """Release one raw-queue identity lock and preserve typed failure evidence."""
    decision = deps.release_identity_lock_decision(lock)
    if type(decision) is IdentityLockReleaseDecision and decision.released:
        return True
    reason = (
        decision.reason
        if type(decision) is IdentityLockReleaseDecision
        else "process_queue_identity_lock_release_decision_invalid"
    )
    deps.record_suppressed("raw_publish_identity_lock_release_failed", RuntimeError(reason))
    return False


__all__ = (
    "acquire_raw_queue_identity_lock",
    "release_raw_queue_identity_lock",
)
