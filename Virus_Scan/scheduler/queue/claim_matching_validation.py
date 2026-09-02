"""Validation and failure handling for process-queue matching claims."""
from Virus_Scan.scheduler.queue.claim_failures import (
    job_with_claim_failure as _job_with_claim_failure,
    path_name as _claim_path_name,
    validation_reason as _validation_reason,
)
from Virus_Scan.scheduler.queue.claim_matching_support import quarantine_claim_matching_exception


CLAIM_MATCHING_HANDLED_EXCEPTIONS = (
    FileNotFoundError,
    PermissionError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)


def claim_matching_claimed_result(queue_dir: object, dst: object, job: object, deps: object) -> object:
    """Validate, deduplicate, merge metadata, and return the claimed job."""
    try:
        claimed_job, validation_error = deps.validate_claim_job(queue_dir, job)
        if validation_error:
            try:
                if isinstance(validation_error, dict):
                    claimed_job = _job_with_claim_failure(claimed_job, validation_error)
                deps.quarantine_invalid_claim(
                    dst,
                    reason=_validation_reason(validation_error, "queue_claim_invalid"),
                    job=claimed_job,
                    identity=deps.queue_job_identity(claimed_job, _claim_path_name(dst)),
                )
            except CLAIM_MATCHING_HANDLED_EXCEPTIONS as exc:
                deps.record_suppressed(
                    "queue_claim_matching_validation_quarantine_failed",
                    exc,
                    extra={"claim_path": str(dst)},
                    fatal=True,
                )
            return None
        try:
            if not deps.duplicate_live_guard(queue_dir, dst, claimed_job):
                _claim_matching_quarantine_claim(
                    dst,
                    "queue_claim_matching_duplicate_live_guard_blocked",
                    claimed_job,
                    deps,
                )
                return None
        except CLAIM_MATCHING_HANDLED_EXCEPTIONS as exc:
            deps.record_suppressed(
                "queue_claim_matching_duplicate_live_guard_exception_failed_closed",
                exc,
                extra={"claim_path": str(dst)},
                fatal=True,
            )
            _claim_matching_quarantine_claim(
                dst,
                "queue_claim_matching_duplicate_live_guard_exception",
                claimed_job,
                deps,
            )
            return None
        try:
            claimed_job = deps.merge_claim_meta_into_job(dst, claimed_job)
        except CLAIM_MATCHING_HANDLED_EXCEPTIONS as exc:
            deps.record_suppressed(
                "queue_claim_matching_meta_merge_failed_closed",
                exc,
                extra={"claim_path": str(dst)},
                fatal=True,
            )
            _claim_matching_quarantine_claim(dst, "queue_claim_matching_meta_merge_failed", claimed_job, deps)
            return None
        return claimed_job, dst
    except CLAIM_MATCHING_HANDLED_EXCEPTIONS as exc:
        failure_info = deps.claim_matching_exception_info(job, exc)
        quarantine_claim_matching_exception(
            dst=dst,
            job=job,
            failure_info=failure_info,
            record_suppressed=deps.record_suppressed,
            quarantine_failed_reason=deps.claim_matching_exception_quarantine_failed_reason(),
            quarantine_invalid_claim=deps.quarantine_invalid_claim,
            queue_job_identity=deps.queue_job_identity,
            claim_path_name=_claim_path_name,
            job_with_claim_failure=_job_with_claim_failure,
        )
        return None


def _claim_matching_quarantine_claim(dst: object, reason: str, claimed_job: object, deps: object) -> None:
    deps.quarantine_invalid_claim(
        dst,
        reason=reason,
        job=claimed_job,
        identity=deps.queue_job_identity(claimed_job, _claim_path_name(dst)),
    )
