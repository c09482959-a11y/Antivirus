"""Progress-gate helpers for per-item orphan recovery."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.queue.orphan_recovery_gates import (
    apply_raw_owner_reclaim_gate,
    apply_raw_stage_reclaim_gate,
)


@dataclass(frozen=True, slots=True)
class ReclaimProgressGateOutcome:
    """Raw-stage/raw-owner gate result for one reclaimed active job."""

    should_continue: bool
    timeout_expired: bool
    checkpoint_stalled: bool


def apply_reclaim_progress_gates(
    *,
    job: object,
    queue_dir: object,
    claim_age: float,
    progress_age: float,
    file_timeout: float,
    progress_stall: float,
    heartbeat_fresh: bool,
    pid_alive: bool,
    raw_stage_progress_recent: object,
    file_has_recent_raw_owner_progress: object,
    timeout_expired: bool,
    checkpoint_stalled: bool,
    evidence_records: list[object],
) -> ReclaimProgressGateOutcome:
    """Apply raw-stage and raw-owner reclaim gates in replayable order."""

    should_continue, timeout_expired, checkpoint_stalled = apply_raw_stage_reclaim_gate(
        job=job,
        queue_dir=queue_dir,
        claim_age=claim_age,
        progress_age=progress_age,
        file_timeout=file_timeout,
        progress_stall=progress_stall,
        heartbeat_fresh=heartbeat_fresh,
        pid_alive=pid_alive,
        raw_stage_progress_recent=raw_stage_progress_recent,
        timeout_expired=timeout_expired,
        checkpoint_stalled=checkpoint_stalled,
        evidence_records=evidence_records,
    )
    if should_continue:
        return ReclaimProgressGateOutcome(True, timeout_expired, checkpoint_stalled)
    should_continue, timeout_expired, checkpoint_stalled = apply_raw_owner_reclaim_gate(
        job=job,
        queue_dir=queue_dir,
        claim_age=claim_age,
        progress_age=progress_age,
        file_timeout=file_timeout,
        progress_stall=progress_stall,
        file_has_recent_raw_owner_progress=file_has_recent_raw_owner_progress,
        timeout_expired=timeout_expired,
        checkpoint_stalled=checkpoint_stalled,
        evidence_records=evidence_records,
    )
    return ReclaimProgressGateOutcome(should_continue, timeout_expired, checkpoint_stalled)


__all__ = ("ReclaimProgressGateOutcome", "apply_reclaim_progress_gates")
