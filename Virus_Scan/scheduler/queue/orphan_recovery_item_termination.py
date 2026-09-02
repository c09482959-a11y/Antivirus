"""Worker termination helper for per-item orphan recovery."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_record_suppressed as _process_queue_record_suppressed,
)
from Virus_Scan.scheduler.queue.orphan_recovery_worker_termination import (
    terminate_reclaimed_worker,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class ReclaimTerminationRequest:
    """Canonical request for one reclaimed active-job owner termination."""

    checkpoint_stalled: object
    timeout_expired: object
    pid_alive: object
    worker_terminator: object
    pid: object
    reason_stage: str
    source_path: object
    queue_dir: object
    job: object
    evidence_records: list[Mapping[str, object]]


@dataclass(frozen=True, slots=True)
class ReclaimTerminationOutcome:
    """Replayable termination result for one reclaimed active job."""

    should_continue: bool
    owner_killed: bool
    termination_evidence: Mapping[str, object]
    killed: int


def terminate_reclaim_owner_if_needed(request: ReclaimTerminationRequest) -> ReclaimTerminationOutcome:
    """Terminate the stale owner when reclaim policy requires it."""

    if not ((request.checkpoint_stalled or request.timeout_expired) and request.pid_alive):
        return ReclaimTerminationOutcome(
            should_continue=False,
            owner_killed=False,
            termination_evidence={},
            killed=0,
        )
    owner_killed, termination_evidence, termination_failed = terminate_reclaimed_worker(
        worker_terminator=request.worker_terminator,
        pid=request.pid,
        reason_stage=request.reason_stage,
        source_path=request.source_path,
        queue_dir=request.queue_dir,
        job=request.job,
        evidence_records=request.evidence_records,
        record_suppressed=_process_queue_record_suppressed,
    )
    if termination_failed or not owner_killed:
        return ReclaimTerminationOutcome(
            should_continue=True,
            owner_killed=owner_killed,
            termination_evidence=termination_evidence,
            killed=0,
        )
    return ReclaimTerminationOutcome(
        should_continue=False,
        owner_killed=True,
        termination_evidence=termination_evidence,
        killed=1,
    )


__all__ = ("ReclaimTerminationOutcome", "ReclaimTerminationRequest", "terminate_reclaim_owner_if_needed")
