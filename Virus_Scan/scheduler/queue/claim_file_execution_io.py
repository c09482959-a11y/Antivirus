"""Bounded IO and sidecar steps for process-queue file claims."""
from __future__ import annotations

import os

from Virus_Scan.scheduler.runtime.queue_filesystem import (
    queue_atomic_replace as _queue_atomic_replace,
    safe_queue_listdir as _safe_queue_listdir,
)
from Virus_Scan.scheduler.runtime.queue_json import read_json_file
from Virus_Scan.scheduler.queue.authority import (
    process_queue_quarantine_invalid_claim as _queue_quarantine_invalid_claim,
    return_active_claim_to_pending as _queue_return_active_claim_to_pending,
)
from Virus_Scan.scheduler.queue.claim_candidates import (
    pending_claim_names as _pending_claim_names,
)
from Virus_Scan.scheduler.queue.claim_sidecar import _queue_claim_sidecar_from_job
from Virus_Scan.scheduler.queue.identity import (
    queue_is_job_json_name as _queue_is_job_json_name,
)

_CLAIM_IO_EXCEPTIONS = (FileNotFoundError, PermissionError, OSError)
_CLAIM_STEP_EXCEPTIONS = (
    FileNotFoundError,
    PermissionError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)


def claim_pending_names(pending: object, record_suppressed: object) -> object:
    """Return pending claim names, failing closed when the pending dir is gone."""
    try:
        return _pending_claim_names(
            pending,
            listdir=_safe_queue_listdir,
            is_job_name=_queue_is_job_json_name,
            limit=256,
            record_failure=record_suppressed,
        )
    except FileNotFoundError:
        return ()


def pending_job_or_quarantine(src: object) -> object:
    """Read a pending job or quarantine unreadable pending content."""
    job = read_json_file(src, default=None)
    if isinstance(job, dict):
        return job
    _queue_quarantine_invalid_claim(
        src,
        reason="queue_claim_unreadable_pending_job",
        job={"queue_job_unreadable": True},
        identity=None,
    )
    return None


def active_claim_destination(
    active: object,
    worker_id: object,
    name: object,
    record_suppressed: object,
    claim_destination_name: object,
) -> object:
    """Build the active claim destination through the canonical name owner."""
    return active / claim_destination_name(
        worker_id,
        name,
        worker_pid=os.getpid(),
        record_suppressed=record_suppressed,
    )


def move_pending_claim(src: object, dst: object) -> bool:
    """Move a pending job into active claim ownership."""
    try:
        return bool(
            _queue_atomic_replace(
                src,
                dst,
                log_context="queue_claim_pending_to_active",
            )
        )
    except _CLAIM_IO_EXCEPTIONS:
        return False


def claim_sidecar_written_or_returned(
    dst: object,
    pending_path: object,
    job: object,
    worker_id: object,
    record_suppressed: object,
) -> bool:
    """Write the claim sidecar or return the active claim to pending."""
    try:
        if _queue_claim_sidecar_from_job(
            dst,
            job,
            worker_id=worker_id,
            progress_marker="claiming",
        ):
            return True
        _queue_return_active_claim_to_pending(
            dst,
            pending_path,
            log_context="queue_claim_sidecar_failed_back_to_pending",
            telemetry_stage="queue_claim_sidecar_failed_return_failed",
        )
        return False
    except _CLAIM_STEP_EXCEPTIONS as exc:
        record_suppressed(
            "queue_claim_sidecar_exception",
            exc,
            extra={"claim_path": str(dst)},
            fatal=True,
        )
        _queue_return_active_claim_to_pending(
            dst,
            pending_path,
            log_context="queue_claim_sidecar_exception_back_to_pending",
            telemetry_stage="queue_claim_sidecar_exception_return_failed",
        )
        return False


__all__ = (
    "active_claim_destination",
    "claim_pending_names",
    "claim_sidecar_written_or_returned",
    "move_pending_claim",
    "pending_job_or_quarantine",
)
