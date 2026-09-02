"""Stage 1560 Phase 4 deterministic scheduler loop guard tests."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.runtime.loop_guard import (
    SchedulerLoopGuard,
    SchedulerLoopGuardAdvanceRequest,
    SchedulerLoopGuardState,
    advance_scheduler_loop_guard,
)


def _advance(guard, state, *, now=0.0, progress_total=0, pending=1, active=0, completed=0, failed=0, workers=1, queue_live=1):
    return advance_scheduler_loop_guard(SchedulerLoopGuardAdvanceRequest(
        guard,
        state,
        now=now,
        progress_total=progress_total,
        pending_count=pending,
        active_count=active,
        completed_count=completed,
        failed_count=failed,
        worker_live_count=workers,
        queue_live_count=queue_live,
    ))


def test_stage1560_loop_guard_allows_normal_progress() -> None:
    guard = SchedulerLoopGuard("process_queue_monitor", 10, 2, 10.0, "queue_drain_stalled")
    state = SchedulerLoopGuardState.start(now=0.0, progress_total=0)

    first = _advance(guard, state, now=1.0, progress_total=1, completed=1)
    second = _advance(guard, first.state, now=2.0, progress_total=2, completed=2)

    assert first.exhausted is False
    assert second.exhausted is False
    assert second.state.no_progress_iterations == 0


def test_stage1560_loop_guard_exits_on_max_iterations_with_evidence() -> None:
    guard = SchedulerLoopGuard("process_queue_monitor", 1, 100, 10.0, "queue_drain_stalled")
    state = SchedulerLoopGuardState.start(now=0.0, progress_total=0)

    first = _advance(guard, state, now=1.0)
    second = _advance(guard, first.state, now=2.0)

    assert second.exhausted is True
    assert second.reason == "scheduler_loop_guard_exhausted"
    assert second.evidence["final_json_must_record"] is True
    assert second.evidence["replay_must_record"] is True


def test_stage1560_loop_guard_exits_on_no_progress_with_queue_drain_evidence() -> None:
    guard = SchedulerLoopGuard("process_queue_monitor", 100, 1, 10.0, "queue_drain_stalled")
    state = SchedulerLoopGuardState.start(now=0.0, progress_total=0)

    first = _advance(guard, state, now=1.0)
    second = _advance(guard, first.state, now=2.0)

    assert second.exhausted is True
    assert second.reason == "queue_drain_stalled"
    assert second.evidence["error_category"] == "queue_drain_stalled"
    assert second.evidence["context"]["scheduler_loop_guard_exhausted"] is True


def test_stage1560_loop_guard_exits_on_wall_time_with_monitor_evidence() -> None:
    guard = SchedulerLoopGuard("process_queue_monitor", 100, 100, 1.0, "queue_drain_stalled")
    state = SchedulerLoopGuardState.start(now=0.0, progress_total=0)

    decision = _advance(guard, state, now=2.0)

    assert decision.exhausted is True
    assert decision.reason == "monitor_wall_time_exceeded"
    assert decision.evidence["timeout_state_affected"] is True


def test_stage1560_parent_worker_and_timeout_guard_reasons_are_evidence_backed() -> None:
    cases = (
        SchedulerLoopGuard("inmemory_parent_loop", 100, 1, 10.0, "parent_loop_stalled"),
        SchedulerLoopGuard("inmemory_worker_loop", 100, 1, 10.0, "worker_loop_stalled"),
        SchedulerLoopGuard("timeout_sweep", 100, 1, 10.0, "timeout_sweep_stall"),
    )
    for guard in cases:
        state = SchedulerLoopGuardState.start(now=0.0, progress_total=0)
        decision = _advance(guard, _advance(guard, state, now=1.0).state, now=2.0)
        assert decision.exhausted is True
        assert decision.evidence["error_category"] == guard.no_progress_reason


def test_stage1560_long_lived_loop_modules_use_scheduler_loop_guard() -> None:
    targets = {
        Path("Virus_Scan/scheduler/orchestration/process_queue_monitor_loop.py"): "apply_process_queue_monitor_guard",
        Path("Virus_Scan/scheduler/orchestration/inmemory_parent_loop.py"): "advance_inmemory_parent_loop_guard",
        Path("Virus_Scan/scheduler/workers/inmemory_worker_process.py"): "advance_scheduler_loop_guard",
    }
    for target, marker in targets.items():
        assert marker in target.read_text(encoding="utf-8")
