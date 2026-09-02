"""Bounded reclaim-action steps for orphan recovery."""
from __future__ import annotations

from dataclasses import dataclass
from typing import MutableMapping, TYPE_CHECKING

from Virus_Scan.scheduler.queue.orphan_recovery_action_execution import prepare_reclaimed_active_job_state
from Virus_Scan.scheduler.queue.orphan_recovery_active_move_steps import reclaim_active_job_to_pending_status

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class ReclaimedActiveMoveResult:
    """Result of moving a reclaimed active job back to pending."""

    moved: bool
    destination_path: Path
    reclaim_deferred: bool | None


def prepare_reclaim_active_move(
    *,
    pending_dir: Path,
    name: str,
    job: MutableMapping[str, object],
    queue_info: MutableMapping[str, object],
    now: float,
    attempt: int,
    info: dict[str, object],
) -> tuple[int, Path]:
    """Prepare retry metadata and destination state for a reclaimed active job."""
    return prepare_reclaimed_active_job_state(
        pending_dir=pending_dir,
        name=name,
        job=job,
        queue_info=queue_info,
        now=now,
        attempt=attempt,
        info=info,
    )


def move_reclaimed_active_job_to_pending(
    *,
    active_dir: Path,
    src: Path,
    dst: Path,
    job: MutableMapping[str, object],
    evidence_records: list[object] | None,
    safe_remove_claim_meta: object,
    cleanup_orphan_claim_meta: object,
    process_queue_env_int: object,
    record_suppressed: object,
    log_error: object,
) -> ReclaimedActiveMoveResult:
    """Move the reclaimed active job to pending and clean associated metadata."""
    moved, destination_path, reclaim_deferred = reclaim_active_job_to_pending_status(
        active_dir=active_dir,
        src=src,
        dst=dst,
        job=job,
        evidence_records=evidence_records,
        safe_remove_claim_meta=safe_remove_claim_meta,
        cleanup_orphan_claim_meta=cleanup_orphan_claim_meta,
        process_queue_env_int=process_queue_env_int,
        record_suppressed=record_suppressed,
        log_error=log_error,
    )
    return ReclaimedActiveMoveResult(moved, destination_path, reclaim_deferred)


__all__ = (
    "ReclaimedActiveMoveResult",
    "move_reclaimed_active_job_to_pending",
    "prepare_reclaim_active_move",
)
