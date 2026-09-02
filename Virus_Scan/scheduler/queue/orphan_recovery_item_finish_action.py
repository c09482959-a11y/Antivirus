"""Finish/requeue action helper for per-item orphan recovery."""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.queue.orphan_recovery_actions import requeue_reclaimed_active_job
from Virus_Scan.scheduler.queue.orphan_recovery_failure_info import build_reclaim_failure_info
from Virus_Scan.scheduler.queue.orphan_recovery_finish import (
    UnretryableReclaimedJobFinishRequest,
    finish_unretryable_reclaimed_job,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


def finish_reclaim_attempt(
    *,
    queue_dir: object,
    active_dir: object,
    pending_dir: object,
    source_path: object,
    name: str,
    job: object,
    queue_info: object,
    now: float,
    retries: int,
    file_timeout: float,
    progress_age: float,
    hb_age: float,
    claim_age: float,
    pid: int,
    pid_alive: bool,
    heartbeat_fresh: bool,
    timeout_decision: object,
    owner_killed: bool,
    termination_evidence: Mapping[str, object],
    killed: int,
    evidence_records: list[Mapping[str, object]],
) -> tuple[int, int, int]:
    """Build failure evidence, then requeue or finalize one reclaimed job."""

    attempt = int(job.get("attempt") or 0)
    info = build_reclaim_failure_info(
        reason_stage=timeout_decision.worker_state,
        timeout_expired=timeout_decision.timeout_expired,
        hard_file_timeout=timeout_decision.hard_file_timeout,
        file_timeout=file_timeout,
        checkpoint_stalled=timeout_decision.checkpoint_stalled,
        progress_age=progress_age,
        hb_age=hb_age,
        claim_age=claim_age,
        pid=pid,
        pid_alive=pid_alive,
        heartbeat_fresh=heartbeat_fresh,
        timeout_evidence=dict(timeout_decision.timeout_evidence),
        owner_killed=owner_killed,
        termination_evidence=dict(termination_evidence),
        recovered=bool(attempt < retries),
        attempt=attempt,
        now_text=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        progress_marker=queue_info.get("progress_marker"),
    )
    if attempt < retries:
        reclaim_result = requeue_reclaimed_active_job(
            queue_dir=queue_dir,
            active_dir=active_dir,
            pending_dir=pending_dir,
            src=source_path,
            name=name,
            job=job,
            queue_info=queue_info,
            now=now,
            attempt=attempt,
            info=info,
            evidence_records=evidence_records,
        )
        if reclaim_result is None:
            return 0, 0, killed
        return (1 if reclaim_result else 0), (0 if reclaim_result else 1), killed
    finish_unretryable_reclaimed_job(
        UnretryableReclaimedJobFinishRequest(
            queue_dir=queue_dir,
            src=source_path,
            info=info,
            job=job,
            evidence_records=evidence_records,
        )
    )
    return 0, 1, killed


__all__ = ("finish_reclaim_attempt",)
