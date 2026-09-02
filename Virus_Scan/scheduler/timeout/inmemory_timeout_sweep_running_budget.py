"""Budget/state extraction for running-worker timeout sweep decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.timeout.inmemory_timeout_record_value_decisions import timeout_record_value_decision
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running_budget_steps import (
    running_timeout_budget_values,
    running_timeout_record_times,
)



@dataclass(frozen=True, slots=True)
class RunningTimeoutBudgetState:
    """Immutable per-running-job timeout budget snapshot."""

    pid: object
    running_at: float
    last_heartbeat: float
    last_progress: float
    heartbeat_age: float
    progress_age: float
    budget_info: Mapping[str, object]
    heartbeat_budget: float
    progress_budget: float
    hard_budget: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "running_at", scheduler_float(value=self.running_at, default=0.0, reason="running_at_malformed", non_finite_reason="running_at_non_finite")[0])
        object.__setattr__(self, "last_heartbeat", scheduler_float(value=self.last_heartbeat, default=0.0, reason="last_heartbeat_malformed", non_finite_reason="last_heartbeat_non_finite")[0])
        object.__setattr__(self, "last_progress", scheduler_float(value=self.last_progress, default=0.0, reason="last_progress_malformed", non_finite_reason="last_progress_non_finite")[0])
        object.__setattr__(self, "heartbeat_age", scheduler_float(value=self.heartbeat_age, default=0.0, reason="heartbeat_age_malformed", non_finite_reason="heartbeat_age_non_finite")[0])
        object.__setattr__(self, "progress_age", scheduler_float(value=self.progress_age, default=0.0, reason="progress_age_malformed", non_finite_reason="progress_age_non_finite")[0])
        object.__setattr__(self, "budget_info", immutable_mapping(self.budget_info if type(self.budget_info) is dict else {}))
        object.__setattr__(self, "heartbeat_budget", scheduler_float(value=self.heartbeat_budget, default=0.0, reason="heartbeat_budget_malformed", non_finite_reason="heartbeat_budget_non_finite")[0])
        object.__setattr__(self, "progress_budget", scheduler_float(value=self.progress_budget, default=0.0, reason="progress_budget_malformed", non_finite_reason="progress_budget_non_finite")[0])
        object.__setattr__(self, "hard_budget", scheduler_float(value=self.hard_budget, default=0.0, reason="hard_budget_malformed", non_finite_reason="hard_budget_non_finite")[0])



def build_running_timeout_budget_state(
    *,
    jid: object,
    rec: Mapping[str, object],
    now: float,
    heartbeat_stale_sec: float,
    progress_stale_sec: float,
    base_pf_timeout: float,
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> RunningTimeoutBudgetState:
    """Return immutable age/budget facts for a running job without mutating queue state."""

    pid = timeout_record_value_decision(rec, "pid").as_value()
    times = running_timeout_record_times(
        jid=jid,
        rec=rec,
        pid=pid,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    budgets = running_timeout_budget_values(
        jid=jid,
        rec=rec,
        pid=pid,
        heartbeat_stale_sec=heartbeat_stale_sec,
        progress_stale_sec=progress_stale_sec,
        base_pf_timeout=base_pf_timeout,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return RunningTimeoutBudgetState(
        pid=pid,
        running_at=times.running_at,
        last_heartbeat=times.last_heartbeat,
        last_progress=times.last_progress,
        heartbeat_age=now - times.last_heartbeat if times.last_heartbeat else 0.0,
        progress_age=now - times.last_progress if times.last_progress else 0.0,
        budget_info=budgets.budget_info,
        heartbeat_budget=budgets.heartbeat_budget,
        progress_budget=budgets.progress_budget,
        hard_budget=budgets.hard_budget,
    )


__all__ = ("RunningTimeoutBudgetState", "build_running_timeout_budget_state")
