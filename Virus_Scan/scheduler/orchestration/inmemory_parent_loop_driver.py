"""Bounded driver for the in-memory parent loop."""
from __future__ import annotations

from dataclasses import dataclass
import time


from Virus_Scan.scheduler.orchestration.inmemory_parent_iteration import (
    dispatch_longlived_parent_jobs,
    handle_next_inmemory_parent_result_iteration,
    reconcile_or_wait_for_empty_drain,
    run_inmemory_parent_maintenance_iteration,
    run_inmemory_respawn_sweep_iteration,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_loop_guard import (
    advance_inmemory_parent_loop_guard,
    publish_inmemory_parent_loop_guard_exhaustion,
    start_inmemory_parent_loop_guard,
    startup_recovery_decision,
)


@dataclass(frozen=True, slots=True)
class LonglivedParentLoopRequest:
    setup: object
    root: object
    total_files: int
    per_file_timeout_sec: float
    startup_recovery_deadline: float
    partial_output_path: object
    partial_output_every: int
    progress_every: int
    throttle_sec: float
    result_retainer: object
    derived_cache_writer: object
    recoverable_exceptions: tuple[type[BaseException], ...]


def drive_longlived_parent_loop(request: LonglivedParentLoopRequest) -> bool:
    setup = request.setup
    submitted = 0
    last_log = time.time()
    last_progress_total = 0
    respawn_sequence = 0
    loop_guard, loop_guard_state = start_inmemory_parent_loop_guard(
        total_work=request.total_files,
        per_item_timeout_sec=request.per_file_timeout_sec,
        now=time.time(),
    )
    while setup.pending or setup.active or setup.recovery.completed < request.total_files:
        now = time.time()
        startup_decision = startup_recovery_decision(
            setup,
            deadline=request.startup_recovery_deadline,
            now=now,
        )
        if startup_decision.required:
            return True
        guard_decision = advance_inmemory_parent_loop_guard(setup, loop_guard, loop_guard_state, now=now)
        loop_guard_state = guard_decision.state
        if guard_decision.exhausted:
            publish_inmemory_parent_loop_guard_exhaustion(
                setup,
                guard_decision,
                recoverable_exceptions=request.recoverable_exceptions,
            )
            break
        submitted += dispatch_longlived_parent_jobs(setup)
        if handle_next_inmemory_parent_result_iteration(
            setup,
            root=request.root,
            partial_output_path=request.partial_output_path,
            partial_output_every=request.partial_output_every,
            started_at=now,
            progress_every=request.progress_every,
            throttle_sec=request.throttle_sec,
            result_retainer=request.result_retainer,
            derived_cache_writer=request.derived_cache_writer,
            recoverable_exceptions=request.recoverable_exceptions,
        ):
            continue
        respawn_sequence = run_inmemory_respawn_sweep_iteration(
            setup,
            respawn_sequence,
            recoverable_exceptions=request.recoverable_exceptions,
        )
        maintenance_output = run_inmemory_parent_maintenance_iteration(
            setup,
            now=time.time(),
            last_log=last_log,
            progress_every=request.progress_every,
            total_files=request.total_files,
            last_progress_total=last_progress_total,
            recoverable_exceptions=request.recoverable_exceptions,
        )
        last_progress_total = maintenance_output.last_progress_total
        last_log = maintenance_output.last_log
        should_continue, should_break = reconcile_or_wait_for_empty_drain(
            setup,
            submitted=submitted,
            total_files=request.total_files,
        )
        if should_continue:
            continue
        if should_break:
            break
    return False


__all__ = ("LonglivedParentLoopRequest", "drive_longlived_parent_loop")
