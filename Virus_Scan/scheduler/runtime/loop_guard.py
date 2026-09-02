"""Deterministic scheduler loop guard entrypoint."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.runtime.loop_guard_contracts import (
    SchedulerLoopGuard,
    SchedulerLoopGuardDecision,
    SchedulerLoopGuardState,
)
from Virus_Scan.scheduler.runtime.loop_guard_evidence import loop_guard_evidence
from Virus_Scan.scheduler.runtime.loop_guard_steps import (
    build_next_loop_guard_state,
    decide_loop_guard_reason,
    normalize_loop_guard,
    normalize_loop_guard_state,
    parse_loop_guard_inputs,
)


@dataclass(frozen=True, slots=True)
class SchedulerLoopGuardAdvanceRequest:
    """Internal request for one deterministic scheduler loop-guard step."""

    guard: SchedulerLoopGuard
    state: SchedulerLoopGuardState
    now: float
    progress_total: int
    pending_count: int
    active_count: int
    completed_count: int
    failed_count: int
    worker_live_count: int
    queue_live_count: int


def advance_scheduler_loop_guard(
    request: SchedulerLoopGuardAdvanceRequest,
) -> SchedulerLoopGuardDecision:
    """Advance one scheduler loop guard through an immutable request."""
    guard = normalize_loop_guard(request.guard)
    state = normalize_loop_guard_state(request.state)
    current_time, progress, count_values, input_evidence = parse_loop_guard_inputs(
        guard,
        state,
        now=request.now,
        progress_total=request.progress_total,
        pending_count=request.pending_count,
        active_count=request.active_count,
        completed_count=request.completed_count,
        failed_count=request.failed_count,
        worker_live_count=request.worker_live_count,
        queue_live_count=request.queue_live_count,
    )
    next_state = build_next_loop_guard_state(
        state,
        current_time=current_time,
        progress=progress,
        input_evidence=input_evidence,
    )
    reason = decide_loop_guard_reason(
        guard,
        next_state,
        current_time=current_time,
        input_evidence=input_evidence,
    )
    if reason == "":
        return SchedulerLoopGuardDecision(next_state, exhausted=False, reason="")
    evidence = loop_guard_evidence(
        guard,
        next_state,
        reason=reason,
        now=current_time,
        counts=count_values,
        input_evidence=input_evidence,
    )
    return SchedulerLoopGuardDecision(
        next_state,
        exhausted=True,
        reason=reason,
        evidence=evidence,
    )




__all__ = (
    'SchedulerLoopGuard',
    'SchedulerLoopGuardAdvanceRequest',
    'SchedulerLoopGuardDecision',
    'SchedulerLoopGuardState',
    'advance_scheduler_loop_guard',
)
