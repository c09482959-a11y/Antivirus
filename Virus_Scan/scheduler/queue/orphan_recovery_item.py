"""Per-active-job orphan recovery handling owned by scheduler queue."""
from __future__ import annotations

from collections.abc import Mapping
from typing import NamedTuple

from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import ActiveClaimState
from Virus_Scan.scheduler.queue.orphan_recovery_item_finish_action import finish_reclaim_attempt
from Virus_Scan.scheduler.queue.orphan_recovery_item_steps import (
    ReclaimTimeoutAttemptRequest,
    classify_reclaim_attempt_timeout,
    snapshot_reclaim_claim_state,
)
from Virus_Scan.scheduler.queue.orphan_recovery_item_termination import (
    ReclaimTerminationRequest,
    terminate_reclaim_owner_if_needed,
)


class ReclaimActiveClaimRequest(NamedTuple):
    """Canonical request for one active claim reclaim attempt."""

    queue_dir: object
    active_dir: object
    pending_dir: object
    source_path: object
    name: str
    claim_state: object
    stale: float
    retries: int
    progress_stall: float
    file_timeout: float
    raw_stage_progress_recent: object
    file_has_recent_raw_owner_progress: object
    worker_terminator: object
    now: float
    timeout_recovery_evidence: list[Mapping[str, object]]


def reclaim_active_claim_state(request: ReclaimActiveClaimRequest) -> tuple[int, int, int]:
    """Reclaim one active claim and return ``(requeued, failed, killed)`` deltas."""

    snapshot = snapshot_reclaim_claim_state(request.claim_state)
    recovery_evidence = (
        request.claim_state.recovery_evidence
        if type(request.claim_state) is ActiveClaimState
        else ()
    )
    for record in recovery_evidence:
        owned_record = materialize_scheduler_mapping(record)
        if type(owned_record) is dict:
            request.timeout_recovery_evidence.append(owned_record)
    timeout_outcome = classify_reclaim_attempt_timeout(
        ReclaimTimeoutAttemptRequest(
            snapshot=snapshot,
            queue_dir=request.queue_dir,
            stale=request.stale,
            progress_stall=request.progress_stall,
            file_timeout=request.file_timeout,
            raw_stage_progress_recent=request.raw_stage_progress_recent,
            file_has_recent_raw_owner_progress=request.file_has_recent_raw_owner_progress,
            evidence_records=request.timeout_recovery_evidence,
            append_timeout_evidence=_append_timeout_decision_evidence,
        )
    )
    if timeout_outcome.should_continue:
        return 0, 0, 0
    timeout_decision = timeout_outcome.timeout_decision
    termination = terminate_reclaim_owner_if_needed(
        ReclaimTerminationRequest(
            checkpoint_stalled=timeout_decision.checkpoint_stalled,
            timeout_expired=timeout_decision.timeout_expired,
            pid_alive=snapshot.pid_alive,
            worker_terminator=request.worker_terminator,
            pid=snapshot.pid,
            reason_stage=timeout_decision.worker_state,
            source_path=request.source_path,
            queue_dir=request.queue_dir,
            job=snapshot.job,
            evidence_records=request.timeout_recovery_evidence,
        )
    )
    if termination.should_continue:
        return 0, 0, 0
    return finish_reclaim_attempt(
        queue_dir=request.queue_dir, active_dir=request.active_dir, pending_dir=request.pending_dir,
        source_path=request.source_path, name=request.name, job=snapshot.job,
        queue_info=snapshot.queue_info, now=request.now, retries=request.retries,
        file_timeout=request.file_timeout, progress_age=snapshot.progress_age,
        hb_age=snapshot.hb_age, claim_age=snapshot.claim_age,
        pid=snapshot.pid, pid_alive=snapshot.pid_alive,
        heartbeat_fresh=snapshot.heartbeat_fresh,
        timeout_decision=timeout_decision, owner_killed=termination.owner_killed,
        termination_evidence=termination.termination_evidence,
        killed=termination.killed, evidence_records=request.timeout_recovery_evidence,
    )


def _append_timeout_decision_evidence(
    timeout_evidence: Mapping[str, object],
    evidence_records: list[Mapping[str, object]],
) -> None:
    evidence = materialize_scheduler_mapping(timeout_evidence)
    evidence_mapping = evidence if type(evidence) is dict else {}
    raw_probe_evidence = materialize_scheduler_mapping(
        dict.get(evidence_mapping, "raw_global_progress_probe_evidence")
    )
    if type(raw_probe_evidence) is dict:
        evidence_records.append(raw_probe_evidence)
    policy_records = tuple(
        dict.get(evidence_mapping, "reclaim_timeout_policy_evidence") or ()
    )
    for policy_evidence in policy_records:
        owned_policy = materialize_scheduler_mapping(policy_evidence)
        if type(owned_policy) is dict:
            evidence_records.append(owned_policy)


__all__ = ("ReclaimActiveClaimRequest", "reclaim_active_claim_state")
