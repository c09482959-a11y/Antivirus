"""Bounded steps for per-active-job orphan recovery."""
from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from Virus_Scan.scheduler.queue.orphan_recovery_item_progress import apply_reclaim_progress_gates
from Virus_Scan.scheduler.queue.orphan_recovery_timeout import classify_reclaim_timeout

if TYPE_CHECKING:
    from collections.abc import Mapping


class ReclaimStateSnapshot(NamedTuple):
    """No-hook materialized values from an active claim state."""

    job: object
    queue_info: object
    hb_age: object
    claim_age: object
    progress_age: object
    pid: object
    pid_alive: object
    heartbeat_fresh: object
    timeout_expired: object
    checkpoint_stalled: object


class ReclaimTimeoutOutcome(NamedTuple):
    """Timeout classification plus a continue marker for a reclaim attempt."""

    timeout_decision: object | None
    should_continue: bool


class ReclaimTimeoutAttemptRequest(NamedTuple):
    """Canonical request for timeout classification of one reclaim attempt."""

    snapshot: ReclaimStateSnapshot
    queue_dir: object
    stale: float
    progress_stall: float
    file_timeout: float
    raw_stage_progress_recent: object
    file_has_recent_raw_owner_progress: object
    evidence_records: list[Mapping[str, object]]
    append_timeout_evidence: object


def snapshot_reclaim_claim_state(claim_state: object) -> ReclaimStateSnapshot:
    """Materialize claim-state fields once without re-reading dynamic attributes later."""
    return ReclaimStateSnapshot(
        claim_state.job,
        claim_state.queue_info,
        claim_state.hb_age,
        claim_state.claim_age,
        claim_state.progress_age,
        claim_state.pid,
        claim_state.pid_alive,
        claim_state.heartbeat_fresh,
        claim_state.timeout_expired,
        claim_state.checkpoint_stalled,
    )


def classify_reclaim_attempt_timeout(request: ReclaimTimeoutAttemptRequest) -> ReclaimTimeoutOutcome:
    """Apply progress gates and timeout policy for a reclaim attempt."""
    snapshot = request.snapshot
    gate_outcome = apply_reclaim_progress_gates(
        job=snapshot.job,
        queue_dir=request.queue_dir,
        claim_age=snapshot.claim_age,
        progress_age=snapshot.progress_age,
        file_timeout=request.file_timeout,
        progress_stall=request.progress_stall,
        heartbeat_fresh=snapshot.heartbeat_fresh,
        pid_alive=snapshot.pid_alive,
        raw_stage_progress_recent=request.raw_stage_progress_recent,
        file_has_recent_raw_owner_progress=request.file_has_recent_raw_owner_progress,
        timeout_expired=snapshot.timeout_expired,
        checkpoint_stalled=snapshot.checkpoint_stalled,
        evidence_records=request.evidence_records,
    )
    if gate_outcome.should_continue:
        return ReclaimTimeoutOutcome(timeout_decision=None, should_continue=True)
    timeout_decision = classify_reclaim_timeout(
        job=snapshot.job,
        queue_dir=request.queue_dir,
        claim_age=snapshot.claim_age,
        progress_age=snapshot.progress_age,
        hb_age=snapshot.hb_age,
        heartbeat_fresh=snapshot.heartbeat_fresh,
        pid_alive=snapshot.pid_alive,
        stale=request.stale,
        file_timeout=request.file_timeout,
        progress_stall=request.progress_stall,
        timeout_expired=gate_outcome.timeout_expired,
        checkpoint_stalled=gate_outcome.checkpoint_stalled,
        raw_stage_progress_recent=request.raw_stage_progress_recent,
    )
    request.append_timeout_evidence(timeout_decision.timeout_evidence, request.evidence_records)
    return ReclaimTimeoutOutcome(
        timeout_decision=timeout_decision,
        should_continue=bool(timeout_decision.continue_claim),
    )


__all__ = (
    "ReclaimStateSnapshot",
    "ReclaimTimeoutAttemptRequest",
    "ReclaimTimeoutOutcome",
    "classify_reclaim_attempt_timeout",
    "snapshot_reclaim_claim_state",
)
