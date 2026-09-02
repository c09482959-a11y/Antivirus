"""Queue-owned timeout/stall classification for orphan recovery."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.timeout.heartbeat_monitor import classify_worker_stall_state
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.queue.orphan_recovery_failure_info import build_reclaim_failure_info
from Virus_Scan.scheduler.queue.orphan_recovery_timeout_policy import (
    build_reclaim_timeout_policy_state,
    probe_reclaim_raw_global_progress,
)


@dataclass(frozen=True)
class ReclaimTimeoutDecision:
    continue_claim: bool
    timeout_expired: bool
    checkpoint_stalled: bool
    hard_file_timeout: float
    progress_stall: float
    stale: float
    worker_state: str
    timeout_evidence: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "timeout_evidence", immutable_mapping(self.timeout_evidence))


def classify_reclaim_timeout(
    *,
    job: dict[str, object],
    queue_dir: object,
    claim_age: float,
    progress_age: float,
    hb_age: float,
    heartbeat_fresh: bool,
    pid_alive: bool,
    stale: float,
    file_timeout: float,
    progress_stall: float,
    timeout_expired: bool,
    checkpoint_stalled: bool,
    raw_stage_progress_recent: Callable[..., bool],
) -> ReclaimTimeoutDecision:
    policy = build_reclaim_timeout_policy_state(
        job=job,
        claim_age=claim_age,
        progress_age=progress_age,
        hb_age=hb_age,
        stale=stale,
        file_timeout=file_timeout,
        progress_stall=progress_stall,
    )
    raw_globally_recent = probe_reclaim_raw_global_progress(
        queue_dir=queue_dir,
        progress_stall=policy.progress_stall,
        raw_stage_progress_recent=raw_stage_progress_recent,
        timeout_evidence=policy.timeout_evidence,
    )
    if heartbeat_fresh and not checkpoint_stalled and policy.claim_age < policy.hard_file_timeout:
        return ReclaimTimeoutDecision(
            continue_claim=True,
            timeout_expired=timeout_expired,
            checkpoint_stalled=checkpoint_stalled,
            hard_file_timeout=policy.hard_file_timeout,
            progress_stall=policy.progress_stall,
            stale=policy.stale,
            worker_state="live",
            timeout_evidence=policy.timeout_evidence,
        )
    if heartbeat_fresh and raw_globally_recent and policy.claim_age < policy.hard_file_timeout:
        return ReclaimTimeoutDecision(
            continue_claim=True,
            timeout_expired=timeout_expired,
            checkpoint_stalled=checkpoint_stalled,
            hard_file_timeout=policy.hard_file_timeout,
            progress_stall=policy.progress_stall,
            stale=policy.stale,
            worker_state="live",
            timeout_evidence=policy.timeout_evidence,
        )
    if pid_alive and not checkpoint_stalled and policy.claim_age < policy.hard_file_timeout and heartbeat_fresh and policy.hb_age < (policy.stale * 4.0):
        return ReclaimTimeoutDecision(
            continue_claim=True,
            timeout_expired=timeout_expired,
            checkpoint_stalled=checkpoint_stalled,
            hard_file_timeout=policy.hard_file_timeout,
            progress_stall=policy.progress_stall,
            stale=policy.stale,
            worker_state="live",
            timeout_evidence=policy.timeout_evidence,
        )
    timeout_expired = policy.claim_age >= policy.hard_file_timeout or (timeout_expired is True and checkpoint_stalled is True)
    stall_classification = classify_worker_stall_state(
        timeout_expired=timeout_expired,
        checkpoint_stalled=checkpoint_stalled,
        heartbeat_fresh=heartbeat_fresh,
        pid_alive=pid_alive,
    )
    return ReclaimTimeoutDecision(
        continue_claim=False,
        timeout_expired=timeout_expired,
        checkpoint_stalled=checkpoint_stalled,
        hard_file_timeout=policy.hard_file_timeout,
        progress_stall=policy.progress_stall,
        stale=policy.stale,
        worker_state=stall_classification.worker_state,
        timeout_evidence=policy.timeout_evidence,
    )


__all__ = ("ReclaimTimeoutDecision", "build_reclaim_failure_info", "classify_reclaim_timeout")
