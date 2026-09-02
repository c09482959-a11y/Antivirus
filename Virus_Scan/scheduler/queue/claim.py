"""Canonical process-queue claim authority ownership.

Owns pending-to-active queue claims, sidecar protection, validation before
execution, and claim rollback/quarantine.  This module does not execute scans,
enforce timeout policy, or serialize evidence.
"""
# Canonical scheduler process queue claim authority state.
import os

from Virus_Scan.scheduler.runtime.queue_filesystem import (
    queue_job_dirs as _queue_job_dirs,
    safe_queue_listdir as _safe_queue_listdir,
)
from Virus_Scan.scheduler.runtime.queue_json import read_json_file
from Virus_Scan.scheduler.queue.claim_candidates import pending_claim_names as _pending_claim_names
from Virus_Scan.scheduler.queue.claim_failures import claim_failure_info
from Virus_Scan.scheduler.queue.claim_matching_steps import ClaimMatchingDeps, claim_matching_job
from Virus_Scan.scheduler.queue.file_job_predicate import process_queue_is_file_job as _process_queue_is_file_job
from Virus_Scan.scheduler.queue.claim_file_execution import (
    ProcessQueueFileClaimRequest,
    claim_process_queue_file_job as _execute_process_queue_file_claim,
)
from Virus_Scan.scheduler.queue.authority import (
    process_queue_merge_claim_meta_into_job as _queue_merge_claim_meta_into_job,
    queue_duplicate_live_guard as _queue_duplicate_live_guard,
    _ensure_process_queue_dirs,
    process_queue_enqueue_guard as _queue_enqueue_guard,
    process_queue_quarantine_invalid_claim as _queue_quarantine_invalid_claim,
    return_active_claim_to_pending as _queue_return_active_claim_to_pending,
)
from Virus_Scan.scheduler.queue.identity import (
    queue_is_job_json_name as _queue_is_job_json_name,
    queue_job_identity as _queue_job_identity,
)
from Virus_Scan.scheduler.ownership.raw_queue_claim_validation import repair_and_validate_claim_job
from Virus_Scan.scheduler.queue.claim_sidecar import _queue_claim_sidecar_from_job
from Virus_Scan.scheduler.evidence.process_queue_errors import record_scheduler_suppressed
from Virus_Scan.scheduler.queue.claim_destination import (
    claim_destination_name as _claim_destination_name,
)

# Process-queue telemetry is owned by scheduler.evidence.process_queue_errors.

def claim_process_queue_job_matching(
    queue_dir: object,
    predicate: object,
    worker_id: object="worker",
    *,
    enqueue_guard: object=_queue_enqueue_guard,
    claim_sidecar_from_job: object=_queue_claim_sidecar_from_job,
    duplicate_live_guard: object=_queue_duplicate_live_guard,
    merge_claim_meta_into_job: object=_queue_merge_claim_meta_into_job,
    record_suppressed: object=record_scheduler_suppressed,
) -> object:
    """Atomically claim one matching job through explicit queue collaborators."""
    deps = ClaimMatchingDeps(
        queue_job_dirs=_queue_job_dirs,
        pending_claim_names=_pending_claim_names,
        safe_queue_listdir=_safe_queue_listdir,
        queue_is_job_json_name=_queue_is_job_json_name,
        read_json_file=read_json_file,
        claim_destination_name=_claim_destination_name,
        validate_claim_job=lambda claim_queue_dir, claimed_job: repair_and_validate_claim_job(
            claim_queue_dir,
            claimed_job,
            worker_pid=os.getpid(),
        ),
        claim_matching_exception_info=lambda job, exc: claim_failure_info(
            "queue_claim_matching_exception",
            exc,
            worker_pid=os.getpid(),
            attempt=(job or {}).get("attempt", 0) if isinstance(job, dict) else 0,
        ),
        claim_matching_exception_quarantine_failed_reason=lambda: (
            "queue_claim_matching_exception_quarantine_failed"
        ),
        enqueue_guard=enqueue_guard,
        claim_sidecar_from_job=claim_sidecar_from_job,
        duplicate_live_guard=duplicate_live_guard,
        merge_claim_meta_into_job=merge_claim_meta_into_job,
        record_suppressed=record_suppressed,
        quarantine_invalid_claim=_queue_quarantine_invalid_claim,
        return_active_claim_to_pending=_queue_return_active_claim_to_pending,
        queue_job_identity=_queue_job_identity,
    )
    return claim_matching_job(queue_dir, predicate, worker_id, deps)

def claim_process_queue_file_job(queue_dir: object, worker_id: object="worker") -> object:
    """Claim only original file jobs, leaving raw_stage jobs for the capped raw pool."""
    return claim_process_queue_job_matching(queue_dir, _process_queue_is_file_job, worker_id=worker_id)

def claim_process_queue_job(
    queue_dir: object,
    worker_id: object="worker",
    *,
    ensure_process_queue_dirs: object=_ensure_process_queue_dirs,
    duplicate_live_guard: object=_queue_duplicate_live_guard,
    merge_claim_meta_into_job: object=_queue_merge_claim_meta_into_job,
    record_suppressed: object=record_scheduler_suppressed,
) -> object:
    """Atomically claim one queued file job through the canonical claim authority."""
    return _execute_process_queue_file_claim(
        ProcessQueueFileClaimRequest(
            queue_dir=queue_dir,
            worker_id=worker_id,
            ensure_process_queue_dirs=ensure_process_queue_dirs,
            duplicate_live_guard=duplicate_live_guard,
            merge_claim_meta_into_job=merge_claim_meta_into_job,
            record_suppressed=record_suppressed,
        )
    )

__all__ = (
    "claim_process_queue_file_job",
    "claim_process_queue_job",
    "claim_process_queue_job_matching",
)
