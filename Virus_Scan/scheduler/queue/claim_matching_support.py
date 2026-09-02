"""Support helpers for bounded process-queue matching claims."""
from __future__ import annotations


def quarantine_claim_matching_exception(
    *,
    dst: object,
    job: object,
    failure_info: object,
    record_suppressed: object,
    quarantine_failed_reason: str,
    quarantine_invalid_claim: object,
    queue_job_identity: object,
    claim_path_name: object,
    job_with_claim_failure: object,
) -> None:
    qj = job_with_claim_failure(job, failure_info)
    try:
        quarantine_invalid_claim(
            dst,
            reason="queue_claim_matching_exception",
            job=qj,
            identity=queue_job_identity(qj, claim_path_name(dst)),
        )
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as quarantine_exc:
        record_suppressed(
            quarantine_failed_reason,
            quarantine_exc,
            extra={"claim_path": str(dst)},
            fatal=True,
        )


__all__ = ("quarantine_claim_matching_exception",)
