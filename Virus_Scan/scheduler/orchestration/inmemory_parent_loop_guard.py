"""In-memory parent loop guard adapter."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_nonnegative_int
from Virus_Scan.scheduler.runtime.loop_guard import (
    SchedulerLoopGuard,
    SchedulerLoopGuardAdvanceRequest,
    SchedulerLoopGuardState,
    advance_scheduler_loop_guard,
)
from Virus_Scan.scheduler.workers.inmemory_worker_death import (
    snapshot_inmemory_worker_liveness,
)


@dataclass(frozen=True, slots=True)
class InMemoryStartupRecoveryDecision:
    required: bool
    reason: str
    completed: int
    live_workers: int
    deadline_expired: bool


def startup_recovery_decision(
    setup: object,
    *,
    deadline: float,
    now: float,
) -> InMemoryStartupRecoveryDecision:
    completed = _completed_count(setup.recovery.completed)
    deadline_expired = now > deadline
    liveness = snapshot_inmemory_worker_liveness(procs=setup.procs)
    if completed > 0:
        return InMemoryStartupRecoveryDecision(
            required=False,
            reason="startup_completion_observed",
            completed=completed,
            live_workers=liveness.live_count,
            deadline_expired=deadline_expired,
        )
    if not deadline_expired:
        return InMemoryStartupRecoveryDecision(
            required=False,
            reason="startup_deadline_not_expired",
            completed=completed,
            live_workers=liveness.live_count,
            deadline_expired=False,
        )
    if liveness.live_count > 0:
        return InMemoryStartupRecoveryDecision(
            required=False,
            reason="startup_workers_alive",
            completed=completed,
            live_workers=liveness.live_count,
            deadline_expired=True,
        )
    return InMemoryStartupRecoveryDecision(
        required=True,
        reason="startup_workers_unavailable",
        completed=completed,
        live_workers=0,
        deadline_expired=True,
    )


def _completed_count(value: object) -> int:
    return scheduler_nonnegative_int(
        value,
        reason="inmemory_parent_loop_completed_rejected",
    )


def start_inmemory_parent_loop_guard(*, total_work: int, per_item_timeout_sec: float, now: float) -> object:
    guard = SchedulerLoopGuard.for_inmemory_parent(
        total_work=total_work,
        per_item_timeout_sec=per_item_timeout_sec,
    )
    return guard, SchedulerLoopGuardState.start(now=now, progress_total=0)


def advance_inmemory_parent_loop_guard(setup: object, guard: SchedulerLoopGuard, state: SchedulerLoopGuardState, *, now: float) -> object:
    completed = _completed_count(setup.recovery.completed)
    return advance_scheduler_loop_guard(
        SchedulerLoopGuardAdvanceRequest(
            guard=guard,
            state=state,
            now=now,
            progress_total=completed,
            pending_count=len(setup.pending),
            active_count=len(setup.active),
            completed_count=completed,
            failed_count=len(setup.failed),
            worker_live_count=len(setup.procs),
            queue_live_count=len(setup.pending) + len(setup.active),
        )
    )


def publish_inmemory_parent_loop_guard_exhaustion(setup: object, guard_decision: object, *, recoverable_exceptions: object) -> None:
    setup.results["__scheduler_loop_guard__"] = {
        "scheduler_failure_evidence": [guard_decision.evidence],
        "scheduler_failure_reason": guard_decision.reason,
        "scheduler_failure": True,
        "final_json_must_record": True,
        "replay_must_record": True,
    }
    try:
        record_scheduler_suppressed(guard_decision.reason, RuntimeError("in-memory parent loop guard exhausted"))
    except recoverable_exceptions as record_exc:
        _ = record_exc


__all__ = (
    "InMemoryStartupRecoveryDecision",
    "advance_inmemory_parent_loop_guard",
    "publish_inmemory_parent_loop_guard_exhaustion",
    "start_inmemory_parent_loop_guard",
    "startup_recovery_decision",
)
