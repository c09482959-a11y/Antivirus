"""Bounded active-claim move steps for orphan recovery."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.orphan_recovery_action_decisions import (
    claim_meta_removed_decision as _claim_meta_removed_decision,
    move_result_succeeded_decision as _move_result_succeeded_decision,
)
from Virus_Scan.scheduler.queue.orphan_recovery_action_execution import (
    cleanup_reclaim_orphan_claims,
    reclaim_action_paths as _reclaim_action_paths,
    record_claim_meta_cleanup_incomplete,
    record_reclaim_action_evidence,
    record_reclaim_move_exception,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace


def cleanup_reclaim_claim_meta_once(
    *,
    safe_remove_claim_meta: object,
    src: object,
    dst: object,
    record_suppressed: object,
) -> None:
    """Remove one active-claim sidecar and record incomplete cleanup evidence."""
    if _claim_meta_removed_decision(safe_remove_claim_meta(src)).removed:
        return
    record_claim_meta_cleanup_incomplete(
        record_suppressed=record_suppressed,
        source_path=src,
        destination_path=dst,
    )


def record_reclaim_move_rejected(
    *,
    evidence_records: list[object] | None,
    src: object,
    dst: object,
    job: object,
) -> None:
    """Record an active-claim move rejection as replayable evidence."""
    record_reclaim_action_evidence(
        evidence_records=evidence_records,
        stage="process_queue_reclaim_active_move_rejected",
        source_path=src,
        destination_path=dst,
        error=RuntimeError("active claim atomic move returned false"),
        error_source="orphan_recovery_actions.queue_atomic_replace",
        job=job,
    )


def record_reclaim_active_source_missing(
    *,
    evidence_records: list[object] | None,
    record_suppressed: object,
    src: object,
    dst: object,
    job: object,
    error: FileNotFoundError,
) -> None:
    """Record a missing reclaimed active source path."""
    record_suppressed(
        "process_queue_reclaim_active_source_missing",
        error,
        fatal=True,
        extra=_reclaim_action_paths(src, dst),
    )
    record_reclaim_action_evidence(
        evidence_records=evidence_records,
        stage="process_queue_reclaim_active_source_missing",
        source_path=src,
        destination_path=dst,
        error=error,
        error_source="orphan_recovery_actions.requeue_reclaimed_active_job",
        job=job,
    )


def record_reclaim_active_move_failed(
    *,
    evidence_records: list[object] | None,
    record_suppressed: object,
    log_error: object,
    src: object,
    dst: object,
    job: object,
    error: BaseException,
) -> None:
    """Record a failed reclaimed active move without collapsing evidence."""
    record_reclaim_move_exception(
        record_suppressed=record_suppressed,
        log_error=log_error,
        source_path=src,
        destination_path=dst,
        error=error,
    )
    record_reclaim_action_evidence(
        evidence_records=evidence_records,
        stage="process_queue_reclaim_active_move_failed",
        source_path=src,
        destination_path=dst,
        error=error,
        error_source="orphan_recovery_actions.requeue_reclaimed_active_job",
        job=job,
    )


def reclaim_active_job_to_pending_status(
    *,
    active_dir: object,
    src: object,
    dst: object,
    job: object,
    evidence_records: list[object] | None,
    safe_remove_claim_meta: object,
    cleanup_orphan_claim_meta: object,
    process_queue_env_int: object,
    record_suppressed: object,
    log_error: object,
) -> tuple[bool, object, bool | None]:
    """Move a reclaimed active job to pending and return primitive status."""
    reclaim_deferred: bool | None = None
    try:
        cleanup_reclaim_claim_meta_once(
            safe_remove_claim_meta=safe_remove_claim_meta,
            src=src,
            dst=dst,
            record_suppressed=record_suppressed,
        )
        if not _move_result_succeeded_decision(queue_atomic_replace(src, dst, log_context="reclaim_active_to_pending")).succeeded:
            record_reclaim_move_rejected(evidence_records=evidence_records, src=src, dst=dst, job=job)
            return False, dst, reclaim_deferred
        cleanup_reclaim_claim_meta_once(
            safe_remove_claim_meta=safe_remove_claim_meta,
            src=src,
            dst=dst,
            record_suppressed=record_suppressed,
        )
        cleanup_reclaim_orphan_claims(
            active_dir=active_dir,
            cleanup_orphan_claim_meta=cleanup_orphan_claim_meta,
            process_queue_env_int=process_queue_env_int,
            record_suppressed=record_suppressed,
        )
    except FileNotFoundError as missing_error:
        record_reclaim_active_source_missing(
            evidence_records=evidence_records,
            record_suppressed=record_suppressed,
            src=src,
            dst=dst,
            job=job,
            error=missing_error,
        )
        return False, dst, reclaim_deferred
    except (PermissionError, OSError, RuntimeError, TypeError, ValueError) as move_error:
        record_reclaim_active_move_failed(
            evidence_records=evidence_records,
            record_suppressed=record_suppressed,
            log_error=log_error,
            src=src,
            dst=dst,
            job=job,
            error=move_error,
        )
        return False, dst, reclaim_deferred
    return True, dst, reclaim_deferred


__all__ = (
    "cleanup_reclaim_claim_meta_once",
    "reclaim_active_job_to_pending_status",
)
