"""Validation, duplicate-guard, and merge steps for file-claim execution."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.authority import (
    process_queue_quarantine_invalid_claim as _queue_quarantine_invalid_claim,
)
from Virus_Scan.scheduler.queue.claim_failures import (
    job_with_claim_failure as _job_with_claim_failure,
    path_name as _claim_path_name,
    quarantine_invalid_claim as _quarantine_invalid_claim,
    validation_reason as _validation_reason,
)
from Virus_Scan.scheduler.queue.claim_file_execution_io import (
    active_claim_destination,
    claim_sidecar_written_or_returned,
    move_pending_claim,
    pending_job_or_quarantine,
)
from Virus_Scan.scheduler.queue.identity import queue_job_identity as _queue_job_identity

_CLAIM_STEP_EXCEPTIONS = (
    FileNotFoundError,
    PermissionError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)


def quarantine_claim_validation_error(
    dst: object,
    job: object,
    validation_error: object,
) -> None:
    """Quarantine a claim that failed repair/validation."""
    if isinstance(validation_error, dict):
        failed_job = _job_with_claim_failure(job, validation_error)
        _quarantine_invalid_claim(
            dst,
            reason=_validation_reason(validation_error, "queue_claim_invalid"),
            job=failed_job,
            identity=_queue_job_identity(failed_job, _claim_path_name(dst)),
            quarantine=_queue_quarantine_invalid_claim,
        )
        return
    _quarantine_invalid_claim(
        dst,
        reason="queue_claim_invalid",
        job=job,
        identity=None,
        quarantine=_queue_quarantine_invalid_claim,
    )


def duplicate_live_guard_allows_claim(
    queue_dir: object,
    dst: object,
    job: object,
    duplicate_live_guard: object,
    record_suppressed: object,
) -> bool:
    """Apply duplicate-live protection and quarantine failed claims."""
    try:
        if duplicate_live_guard(queue_dir, dst, job):
            return True
        _queue_quarantine_invalid_claim(
            dst,
            reason="queue_claim_duplicate_live_guard_blocked",
            job=job,
            identity=_queue_job_identity(job, _claim_path_name(dst)),
        )
        return False
    except _CLAIM_STEP_EXCEPTIONS as exc:
        record_suppressed(
            "queue_claim_duplicate_live_guard_exception_failed_closed",
            exc,
            extra={"claim_path": str(dst)},
            fatal=True,
        )
        _queue_quarantine_invalid_claim(
            dst,
            reason="queue_claim_duplicate_live_guard_exception",
            job=job,
            identity=_queue_job_identity(job, _claim_path_name(dst)),
        )
        return False


def merged_claim_meta_or_quarantined(
    dst: object,
    job: object,
    merge_claim_meta_into_job: object,
    record_suppressed: object,
) -> tuple[bool, object]:
    """Merge claim metadata, preserving a successful None merge result."""
    try:
        return True, merge_claim_meta_into_job(dst, job)
    except _CLAIM_STEP_EXCEPTIONS as exc:
        record_suppressed(
            "queue_claim_meta_merge_failed_closed",
            exc,
            extra={"claim_path": str(dst)},
            fatal=True,
        )
        _queue_quarantine_invalid_claim(
            dst,
            reason="queue_claim_meta_merge_failed",
            job=job,
            identity=_queue_job_identity(job, _claim_path_name(dst)),
        )
        return False, None


def claim_pending_file_job(
    queue_dir: object,
    pending: object,
    active: object,
    name: object,
    worker_id: object,
    duplicate_live_guard: object,
    merge_claim_meta_into_job: object,
    record_suppressed: object,
    repair_claim_job_or_validation_error: object,
    claim_destination_name: object,
) -> tuple[bool, object, object]:
    """Claim, validate, guard, and enrich one pending file job."""
    src = pending / name
    job = pending_job_or_quarantine(src)
    if job is None:
        return False, None, None
    dst = active_claim_destination(
        active,
        worker_id,
        name,
        record_suppressed,
        claim_destination_name,
    )
    if not move_pending_claim(src, dst):
        return False, None, None
    if not claim_sidecar_written_or_returned(
        dst,
        pending / name,
        job,
        worker_id,
        record_suppressed,
    ):
        return False, None, None
    job, validation_error = repair_claim_job_or_validation_error(
        queue_dir,
        dst,
        job,
        record_suppressed,
    )
    if validation_error:
        quarantine_claim_validation_error(dst, job, validation_error)
        return False, None, None
    if not duplicate_live_guard_allows_claim(
        queue_dir,
        dst,
        job,
        duplicate_live_guard,
        record_suppressed,
    ):
        return False, None, None
    merged, job = merged_claim_meta_or_quarantined(
        dst,
        job,
        merge_claim_meta_into_job,
        record_suppressed,
    )
    if not merged:
        return False, None, None
    return True, job, dst


__all__ = ("claim_pending_file_job",)
