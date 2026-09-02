"""Queue-owned file-job claim execution steps.

This module is an internal implementation owner used only by the canonical
claim authority in scheduler.queue.claim.  It does not expose an alternate
claim authority API.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from Virus_Scan.scheduler.runtime.queue_filesystem import (
    queue_job_dirs as _queue_job_dirs,
)
from Virus_Scan.scheduler.ownership.raw_queue_claim_validation import (
    repair_and_validate_claim_job,
)
from Virus_Scan.scheduler.queue.claim_failures import (
    claim_failure_info as _claim_failure_info,
)
from Virus_Scan.scheduler.queue.claim_destination import (
    claim_destination_name as _claim_destination_name,
)
from Virus_Scan.scheduler.queue.claim_file_execution_io import claim_pending_names
from Virus_Scan.scheduler.queue.claim_file_execution_validation import (
    claim_pending_file_job,
)

_CLAIM_STEP_EXCEPTIONS = (
    FileNotFoundError,
    PermissionError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)
_CLAIM_VALIDATION_EXCEPTIONS = _CLAIM_STEP_EXCEPTIONS + (json.JSONDecodeError,)


@dataclass(frozen=True, slots=True)
class ProcessQueueFileClaimRequest:
    """Internal collaborators for one canonical file-job claim attempt."""

    queue_dir: object
    worker_id: object
    ensure_process_queue_dirs: object
    duplicate_live_guard: object
    merge_claim_meta_into_job: object
    record_suppressed: object


def claim_process_queue_file_job(request: ProcessQueueFileClaimRequest) -> object:
    """Atomically claim one queued file job, or return (None, None)."""

    def repair_claim_job_or_validation_error(
        queue_dir_value: object,
        dst: object,
        job: object,
        record_suppressed_value: object,
    ) -> tuple[object, object]:
        try:
            return repair_and_validate_claim_job(
                queue_dir_value,
                job,
                worker_pid=os.getpid(),
            )
        except _CLAIM_VALIDATION_EXCEPTIONS as exc:
            fallback_job = job if isinstance(job, dict) else {"queue_job_unreadable": True}
            record_suppressed_value(
                "queue_claim_validation_exception_failed_closed",
                exc,
                extra={"claim_path": str(dst)},
                fatal=True,
            )
            validation_error = _claim_failure_info(
                "queue_claim_validation_exception",
                exc,
                worker_pid=os.getpid(),
                attempt=fallback_job.get("attempt") if isinstance(fallback_job, dict) else None,
            )
            return fallback_job, validation_error

    queue_dir = request.queue_dir
    pending, active, _, _ = _queue_job_dirs(queue_dir)
    request.ensure_process_queue_dirs(queue_dir)
    names = claim_pending_names(pending, request.record_suppressed)
    for name in names:
        claimed, job, dst = claim_pending_file_job(
            queue_dir,
            pending,
            active,
            name,
            request.worker_id,
            request.duplicate_live_guard,
            request.merge_claim_meta_into_job,
            request.record_suppressed,
            repair_claim_job_or_validation_error,
            _claim_destination_name,
        )
        if claimed:
            return job, dst
    return None, None


__all__ = ("ProcessQueueFileClaimRequest", "claim_process_queue_file_job")
