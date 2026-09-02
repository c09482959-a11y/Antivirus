"""Process-queue monitor loop-guard adapter."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.runtime.loop_guard import (
    SchedulerLoopGuard,
    SchedulerLoopGuardAdvanceRequest,
    SchedulerLoopGuardState,
    advance_scheduler_loop_guard,
)


@dataclass(frozen=True, slots=True)
class ProcessQueueMonitorGuardObservation:
    """Materialized queue counts consumed by the canonical loop guard."""

    now: float
    accounted_total: int
    file_pending_count: int
    file_active_count: int
    file_done_count: int
    file_failed_count: int
    raw_live: int
    raw_done: int
    raw_failed: int
    live_workers: int


@dataclass(frozen=True, slots=True)
class ProcessQueueMonitorGuardApplyRequest:
    """Per-iteration mutable publication boundary for loop-guard application."""

    now: float
    accounted_total: int
    evidence_records: list[object]
    had_error: bool


def start_process_queue_monitor_guard(*, total_work: int, sleep_sec: float, per_item_timeout_sec: float, now: float) -> object:
    guard = SchedulerLoopGuard.for_monitor(
        total_work=total_work,
        sleep_sec=sleep_sec,
        per_item_timeout_sec=per_item_timeout_sec,
    )
    return guard, SchedulerLoopGuardState.start(now=now, progress_total=0)


def advance_process_queue_monitor_guard(
    guard: SchedulerLoopGuard,
    state: SchedulerLoopGuardState,
    observation: ProcessQueueMonitorGuardObservation,
) -> object:
    return advance_scheduler_loop_guard(
        SchedulerLoopGuardAdvanceRequest(
            guard=guard,
            state=state,
            now=observation.now,
            progress_total=observation.accounted_total,
            pending_count=observation.file_pending_count,
            active_count=observation.file_active_count,
            completed_count=observation.file_done_count + observation.raw_done,
            failed_count=observation.file_failed_count + observation.raw_failed,
            worker_live_count=observation.live_workers,
            queue_live_count=(
                observation.file_pending_count
                + observation.file_active_count
                + observation.raw_live
            ),
        )
    )


def apply_process_queue_monitor_guard(
    guard: SchedulerLoopGuard,
    state: SchedulerLoopGuardState,
    iteration_start: object,
    request: ProcessQueueMonitorGuardApplyRequest,
) -> object:
    counts = iteration_start.counts
    decision = advance_process_queue_monitor_guard(
        guard,
        state,
        ProcessQueueMonitorGuardObservation(
            now=request.now,
            accounted_total=request.accounted_total,
            file_pending_count=iteration_start.file_pending_count,
            file_active_count=iteration_start.file_active_count,
            file_done_count=iteration_start.file_done_count,
            file_failed_count=iteration_start.file_failed_count,
            raw_live=iteration_start.raw_live,
            raw_done=counts["raw_done"],
            raw_failed=counts["raw_failed"],
            live_workers=iteration_start.live_workers,
        ),
    )
    if decision.exhausted:
        request.evidence_records.append(decision.evidence)
        return decision.state, True, True
    return decision.state, request.had_error, False


__all__ = (
    "ProcessQueueMonitorGuardApplyRequest",
    "ProcessQueueMonitorGuardObservation",
    "advance_process_queue_monitor_guard",
    "apply_process_queue_monitor_guard",
    "start_process_queue_monitor_guard",
)
