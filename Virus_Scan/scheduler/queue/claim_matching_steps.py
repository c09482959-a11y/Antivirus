import os
from dataclasses import dataclass

from Virus_Scan.scheduler.queue.claim_matching_validation import (
    CLAIM_MATCHING_HANDLED_EXCEPTIONS,
    claim_matching_claimed_result,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace


@dataclass(frozen=True)
class ClaimMatchingDeps:
    queue_job_dirs: object
    pending_claim_names: object
    safe_queue_listdir: object
    queue_is_job_json_name: object
    read_json_file: object
    claim_destination_name: object
    validate_claim_job: object
    claim_matching_exception_info: object
    claim_matching_exception_quarantine_failed_reason: object
    enqueue_guard: object
    claim_sidecar_from_job: object
    duplicate_live_guard: object
    merge_claim_meta_into_job: object
    record_suppressed: object
    quarantine_invalid_claim: object
    return_active_claim_to_pending: object
    queue_job_identity: object


def claim_matching_job(queue_dir: object, predicate: object, worker_id: object, deps: ClaimMatchingDeps) -> object:
    pending, active, _done, _failed = deps.queue_job_dirs(queue_dir)
    try:
        names = deps.pending_claim_names(
            pending,
            listdir=deps.safe_queue_listdir,
            is_job_name=deps.queue_is_job_json_name,
            limit=512,
            record_failure=deps.record_suppressed,
        )
    except FileNotFoundError:
        names = ()
    for name in names:
        src = pending / name
        job = deps.read_json_file(src, default=None)
        if not isinstance(job, dict):
            continue
        if not predicate(job):
            continue
        try:
            enqueue_allowed = bool(deps.enqueue_guard(queue_dir, job, states=("active", "done")))
            if not enqueue_allowed:
                deps.quarantine_invalid_claim(
                    src,
                    reason="duplicate_pending_raw_blocked_before_claim",
                    job=job,
                    identity=deps.queue_job_identity(job, name),
                )
        except CLAIM_MATCHING_HANDLED_EXCEPTIONS as exc:
            deps.record_suppressed(
                "queue_claim_matching_enqueue_guard_exception_failed_closed",
                exc,
                extra={"pending_path": str(src)},
                fatal=True,
            )
            deps.quarantine_invalid_claim(
                src,
                reason="queue_claim_matching_enqueue_guard_exception",
                job=job,
                identity=deps.queue_job_identity(job, name),
            )
            enqueue_allowed = False
        if not enqueue_allowed:
            continue
        claim_name = deps.claim_destination_name(
            worker_id,
            name,
            worker_pid=os.getpid(),
            record_suppressed=deps.record_suppressed,
        )
        dst = active / claim_name
        try:
            replaced = bool(
                queue_atomic_replace(
                    src,
                    dst,
                    log_context="queue_claim_matching_pending_to_active",
                )
            )
        except (FileNotFoundError, PermissionError, OSError):
            replaced = False
        if not replaced:
            continue
        try:
            progress_marker = (
                "claiming_raw_match"
                if isinstance(job, dict) and job.get("job_type") == "raw_stage"
                else "claiming"
            )
            sidecar_ready = bool(
                deps.claim_sidecar_from_job(
                    dst,
                    job,
                    worker_id=worker_id,
                    progress_marker=progress_marker,
                )
            )
            if not sidecar_ready:
                deps.return_active_claim_to_pending(
                    dst,
                    pending / name,
                    log_context="queue_claim_matching_sidecar_failed_back_to_pending",
                    telemetry_stage="queue_claim_matching_sidecar_failed_return_failed",
                )
        except CLAIM_MATCHING_HANDLED_EXCEPTIONS as exc:
            deps.record_suppressed(
                "queue_claim_matching_sidecar_exception",
                exc,
                extra={"claim_path": str(dst)},
                fatal=True,
            )
            deps.return_active_claim_to_pending(
                dst,
                pending / name,
                log_context="queue_claim_matching_sidecar_exception_back_to_pending",
                telemetry_stage="queue_claim_matching_sidecar_exception_return_failed",
            )
            sidecar_ready = False
        if sidecar_ready:
            return claim_matching_claimed_result(queue_dir, dst, job, deps)
    return None, None
