"""Bounded running-timeout budget value extraction helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import safe_record_float
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_budget_values import (
    combined_running_timeout_budget,
    timeout_budget_mapping_for_record,
)


@dataclass(frozen=True, slots=True)
class RunningTimeoutRecordTimes:
    running_at: float
    last_heartbeat: float
    last_progress: float


@dataclass(frozen=True, slots=True)
class RunningTimeoutBudgetValues:
    budget_info: Mapping[str, object]
    heartbeat_budget: float
    progress_budget: float
    hard_budget: float


def running_timeout_record_times(
    *,
    jid: object,
    rec: Mapping[str, object],
    pid: object,
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> RunningTimeoutRecordTimes:
    running_at = safe_record_float(
        record=rec,
        field="running_at",
        default=0.0,
        job_id=jid,
        pid=pid,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    last_heartbeat = safe_record_float(
        record=rec,
        field="last_heartbeat",
        default=running_at,
        job_id=jid,
        pid=pid,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    last_progress = safe_record_float(
        record=rec,
        field="last_progress_time",
        default=running_at,
        job_id=jid,
        pid=pid,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return RunningTimeoutRecordTimes(running_at, last_heartbeat, last_progress)


def running_timeout_budget_values(
    *,
    jid: object,
    rec: Mapping[str, object],
    pid: object,
    heartbeat_stale_sec: float,
    progress_stale_sec: float,
    base_pf_timeout: float,
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> RunningTimeoutBudgetValues:
    budget_info = timeout_budget_mapping_for_record(
        jid=jid,
        rec=rec,
        pid=pid,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    heartbeat_budget = combined_running_timeout_budget(
        policy_value=heartbeat_stale_sec,
        policy_field="heartbeat_stale_sec",
        budget_field="heartbeat_stale_budget",
        jid=jid,
        rec=rec,
        pid=pid,
        budget_info=budget_info,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    progress_budget = combined_running_timeout_budget(
        policy_value=progress_stale_sec,
        policy_field="progress_stale_sec",
        budget_field="stall_budget",
        jid=jid,
        rec=rec,
        pid=pid,
        budget_info=budget_info,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    hard_budget = combined_running_timeout_budget(
        policy_value=base_pf_timeout,
        policy_field="base_pf_timeout",
        budget_field="timeout_budget",
        jid=jid,
        rec=rec,
        pid=pid,
        budget_info=budget_info,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return RunningTimeoutBudgetValues(budget_info, heartbeat_budget, progress_budget, hard_budget)


__all__ = (
    "RunningTimeoutBudgetValues",
    "RunningTimeoutRecordTimes",
    "running_timeout_budget_values",
    "running_timeout_record_times",
)
