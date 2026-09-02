"""Scheduler loop exhaustion evidence construction."""
from __future__ import annotations

from typing import Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord

if TYPE_CHECKING:
    from Virus_Scan.scheduler.runtime.loop_guard_contracts import (
        SchedulerLoopGuard,
        SchedulerLoopGuardState,
    )


def loop_guard_evidence(
    guard: SchedulerLoopGuard,
    state: SchedulerLoopGuardState,
    *,
    reason: str,
    now: float,
    counts: Mapping[str, int],
    input_evidence: tuple[Mapping[str, object], ...],
) -> Mapping[str, object]:
    context = {
        "scheduler_loop_guard_exhausted": True,
        "iteration_count": state.iteration_count,
        "max_iterations": guard.max_iterations,
        "no_progress_iterations": state.no_progress_iterations,
        "max_no_progress_iterations": guard.max_no_progress_iterations,
        "wall_time_sec": round(now - state.start_time, 6),
        "max_wall_time_sec": guard.max_wall_time_sec,
        "last_progress_time": state.last_progress_time,
        "input_evidence": input_evidence,
    }
    context.update(counts)
    return SchedulerEvidenceRecord(
        stage=guard.loop_name,
        state="failed",
        error_category=reason,
        error_source="scheduler.runtime.loop_guard",
        message=guard.loop_name + " exhausted deterministic guard",
        context=context,
        timeout_state_affected=(
            "timeout" in reason or "wall_time" in reason or "stalled" in reason
        ),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=False,
    ).as_dict()


__all__ = ("loop_guard_evidence",)
