"""Execution helpers for active-claim reclaim actions."""
from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_evidence_text,
    scheduler_exception_text,
    scheduler_int,
)
from Virus_Scan.scheduler.queue.orphan_recovery_action_decisions import reclaim_job_identifier_decision
from Virus_Scan.scheduler.queue.orphan_recovery_action_evidence import (
    OrphanRecoveryActionEvidenceRequest,
    orphan_recovery_action_evidence,
)
from Virus_Scan.scheduler.queue.recovery_contract import reset_queue_retry_runtime_metadata

if TYPE_CHECKING:
    from pathlib import Path


def reclaim_attempt_value(attempt: object) -> int:
    """Return a no-hook normalized reclaim attempt count."""
    value, _reason = scheduler_int(
        attempt,
        default=0,
        minimum=0,
        reason="reclaim_attempt_rejected",
    )
    return value


def reclaim_action_paths(source_path: object, destination_path: object) -> dict[str, str]:
    """Project source/destination paths for replayable reclaim evidence."""
    return {
        "source": scheduler_evidence_path(source_path, field_name="reclaim_source_path"),
        "destination": scheduler_evidence_path(destination_path, field_name="reclaim_destination_path"),
    }


def prepare_reclaimed_active_job_state(
    *,
    pending_dir: Path,
    name: object,
    job: MutableMapping[str, object],
    queue_info: MutableMapping[str, object],
    now: float,
    attempt: object,
    info: Mapping[str, object],
) -> tuple[int, Path]:
    """Update job/queue metadata before moving one stale active claim."""
    attempt_value = reclaim_attempt_value(attempt)
    job["attempt"] = attempt_value + 1
    job["reclaimed_from_active"] = True
    hist = job.get("queue_reclaim_history") or []
    if not isinstance(hist, list):
        hist = []
    hist.append(info)
    job["queue_reclaim_history"] = hist[-8:]
    queue_info.update(
        {
            "reclaimed_time": float(now),
            "reclaimed_iso": info["time"],
            "heartbeat_time": None,
            "progress_time": float(now),
            "progress_marker": "requeued_after_stall",
        }
    )
    job["queue_info"] = queue_info
    reset_queue_retry_runtime_metadata(job, now=now, reason="requeued_after_stall")
    name_text = scheduler_evidence_text(
        name,
        missing_text="missing_reclaim_source_name",
        field_name="reclaim_source_name",
    )
    return attempt_value, pending_dir / ("reclaim" + int.__str__(attempt_value + 1).zfill(2) + "_" + name_text)


def record_reclaim_action_evidence(
    *,
    evidence_records: list[Mapping[str, object]] | None,
    stage: str,
    source_path: object,
    destination_path: object,
    error: BaseException,
    error_source: str,
    job: Mapping[str, object],
) -> None:
    """Append typed reclaim action evidence when the caller supplied a sink."""
    if evidence_records is not None:
        evidence_records.append(
            orphan_recovery_action_evidence(OrphanRecoveryActionEvidenceRequest(
                stage=stage,
                action="move_active_claim_to_pending",
                source_path=source_path,
                destination_path=destination_path,
                error=error,
                error_source=error_source,
                job_id=reclaim_job_identifier_decision(job).identifier,
            )).as_record()
        )


def record_claim_meta_cleanup_incomplete(
    *,
    record_suppressed: object,
    source_path: object,
    destination_path: object,
) -> None:
    """Record an incomplete claim-sidecar cleanup as degraded reclaim evidence."""
    record_suppressed(
        "process_queue_reclaim_pre_move_claim_meta_cleanup_incomplete",
        RuntimeError("claim meta cleanup returned false"),
        extra=reclaim_action_paths(source_path, destination_path),
    )


def cleanup_reclaim_orphan_claims(
    *,
    active_dir: object,
    cleanup_orphan_claim_meta: object,
    process_queue_env_int: object,
    record_suppressed: object,
) -> None:
    """Run bounded orphan-claim cleanup after a successful active-to-pending move."""
    orphan_removed = cleanup_orphan_claim_meta(
        active_dir,
        max_remove=process_queue_env_int(
            "UMIGE_QUEUE_ORPHAN_CLAIM_CLEAN_MAX",
            8192,
            minimum=0,
            record_suppressed=record_suppressed,
        ),
    )
    if orphan_removed < 0:
        record_suppressed(
            "process_queue_reclaim_orphan_cleanup_incomplete",
            RuntimeError("orphan claim cleanup failed"),
            extra={"active_dir": scheduler_evidence_path(active_dir, field_name="active_dir")},
        )


def record_reclaim_move_exception(
    *,
    record_suppressed: object,
    log_error: object,
    source_path: object,
    destination_path: object,
    error: BaseException,
) -> None:
    """Record a failed active-claim move through suppressed and log channels."""
    record_suppressed(
        "process_queue_reclaim_move_failed",
        error,
        fatal=True,
        extra=reclaim_action_paths(source_path, destination_path),
    )
    log_error(
        "process queue reclaim move failed: source="
        + scheduler_evidence_path(source_path, field_name="reclaim_source_path")
        + " destination="
        + scheduler_evidence_path(destination_path, field_name="reclaim_destination_path")
        + " detail="
        + scheduler_exception_text(error)
    )


__all__ = (
    "cleanup_reclaim_orphan_claims",
    "prepare_reclaimed_active_job_state",
    "reclaim_action_paths",
    "record_claim_meta_cleanup_incomplete",
    "record_reclaim_action_evidence",
    "record_reclaim_move_exception",
)
