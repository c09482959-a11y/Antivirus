"""Bounded helper steps for scheduler loop guard advancement."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.runtime.loop_guard_contracts import (
    SchedulerLoopGuard,
    SchedulerLoopGuardState,
)
from Virus_Scan.scheduler.runtime.loop_guard_values import (
    guard_float,
    guard_int,
    guard_issue,
)


def normalize_loop_guard(guard: object) -> SchedulerLoopGuard:
    """Return a safe loop guard, recording rejected hostile inputs as evidence."""
    if type(guard) is SchedulerLoopGuard:
        return guard
    return SchedulerLoopGuard(
        "scheduler_loop",
        1,
        1,
        0.0,
        "scheduler_loop_no_progress",
        (guard_issue("guard", guard, "scheduler_loop_guard_rejected"),),
    )


def normalize_loop_guard_state(state: object) -> SchedulerLoopGuardState:
    """Return a safe loop guard state, recording rejected hostile inputs."""
    if type(state) is SchedulerLoopGuardState:
        return state
    return SchedulerLoopGuardState(
        0,
        0,
        0,
        0.0,
        0.0,
        (guard_issue("state", state, "scheduler_loop_guard_state_rejected"),),
    )


def parse_loop_guard_inputs(
    guard: SchedulerLoopGuard,
    state: SchedulerLoopGuardState,
    *,
    now: object,
    progress_total: object,
    pending_count: object,
    active_count: object,
    completed_count: object,
    failed_count: object,
    worker_live_count: object,
    queue_live_count: object,
) -> tuple[float, int, dict[str, int], tuple[Mapping[str, object], ...]]:
    """Parse and materialize the loop-guard numeric inputs without hooks."""
    current_time, time_issue = guard_float(
        now, field_name="now", default_value=state.last_progress_time
    )
    progress, progress_issue = guard_int(
        progress_total,
        field_name="progress_total",
        default_value=state.last_progress_total,
    )
    count_values: dict[str, int] = {}
    count_issues: tuple[Mapping[str, object], ...] = ()
    for field_name, value in (
        ("pending_count", pending_count),
        ("active_count", active_count),
        ("completed_count", completed_count),
        ("failed_count", failed_count),
        ("worker_live_count", worker_live_count),
        ("queue_live_count", queue_live_count),
    ):
        parsed, issue = guard_int(value, field_name=field_name, default_value=0)
        count_values[field_name] = parsed
        count_issues += issue
    input_evidence = (
        tuple(guard.config_evidence)
        + tuple(state.input_evidence)
        + time_issue
        + progress_issue
        + count_issues
    )
    return current_time, progress, count_values, input_evidence


def build_next_loop_guard_state(
    state: SchedulerLoopGuardState,
    *,
    current_time: float,
    progress: int,
    input_evidence: tuple[Mapping[str, object], ...],
) -> SchedulerLoopGuardState:
    """Advance loop-guard state from parsed progress values."""
    made_progress = progress != state.last_progress_total
    return SchedulerLoopGuardState(
        iteration_count=state.iteration_count + 1,
        no_progress_iterations=(
            0 if made_progress else state.no_progress_iterations + 1
        ),
        last_progress_total=progress,
        start_time=state.start_time,
        last_progress_time=current_time if made_progress else state.last_progress_time,
        input_evidence=input_evidence,
    )


def decide_loop_guard_reason(
    guard: SchedulerLoopGuard,
    state: SchedulerLoopGuardState,
    *,
    current_time: float,
    input_evidence: tuple[Mapping[str, object], ...],
) -> str:
    """Return the explicit loop-stop reason, or an empty string to continue."""
    if input_evidence:
        return "scheduler_loop_guard_input_rejected"
    if state.iteration_count > guard.max_iterations:
        return "scheduler_loop_guard_exhausted"
    if state.no_progress_iterations > guard.max_no_progress_iterations:
        return guard.no_progress_reason
    if guard.max_wall_time_sec > 0 and current_time - state.start_time > guard.max_wall_time_sec:
        return "monitor_wall_time_exceeded"
    return ""


__all__ = (
    "build_next_loop_guard_state",
    "decide_loop_guard_reason",
    "normalize_loop_guard",
    "normalize_loop_guard_state",
    "parse_loop_guard_inputs",
)
