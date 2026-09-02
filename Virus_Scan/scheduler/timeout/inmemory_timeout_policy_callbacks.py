"""Timeout-owned safe policy callback boundaries for in-memory sweeps."""
from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_numbers import (
    record_timeout_policy_failure,
    safe_record_float,
    safe_timeout_budget_number,
    timeout_budget_for_record,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int, scheduler_nonnegative_int
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callback_contracts import StagePreExecutionClassifier, StartWaitBudget, TimeoutPolicyFailures, TimeoutPolicyRecord, TimeoutPolicySuppressedRecorder


def safe_start_wait_budget(
    *,
    start_wait_budget: StartWaitBudget,
    job_id: object,
    record: TimeoutPolicyRecord,
    default_budget: float,
    reason: str,
    pid: object | None = None,
    failures: TimeoutPolicyFailures,
    record_scheduler_suppressed: TimeoutPolicySuppressedRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> float:
    """Evaluate queued/assigned wait budget and emit evidence on callback failure."""
    try:
        value = start_wait_budget(record, default_budget)
    except recoverable_exceptions as budget_exc:
        record_timeout_policy_failure(
            failures=failures,
            job_id=job_id,
            record=record,
            reason=reason,
            action="start_wait_budget_failed",
            error=budget_exc,
            source="inmemory_timeout_sweep.start_wait_budget",
            pid=pid,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        default_number, _default_reason = scheduler_float(
            default_budget,
            default=0.0,
            reason="start_wait_budget_default_rejected",
        )
        return default_number
    safe_default_budget, _default_reason = scheduler_float(
        default_budget,
        default=0.0,
        reason="start_wait_budget_default_rejected",
    )
    parsed, parse_reason = scheduler_float(
        value,
        default=safe_default_budget,
        reason="start_wait_budget_return_rejected",
    )
    if parse_reason:
        record_timeout_policy_failure(
            failures=failures,
            job_id=job_id,
            record=record,
            reason=parse_reason,
            action="start_wait_budget_failed",
            error=ValueError(parse_reason),
            source="inmemory_timeout_sweep.start_wait_budget",
            pid=pid,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return safe_default_budget
    return parsed


def safe_stage_is_pre_execution(
    *,
    classifier: StagePreExecutionClassifier,
    stage: str,
    job_id: object,
    record: TimeoutPolicyRecord,
    pid: object,
    failures: TimeoutPolicyFailures,
    record_scheduler_suppressed: TimeoutPolicySuppressedRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    """Classify pre-execution stages without hiding timeout policy callback failures."""
    try:
        value = classifier(stage)
    except recoverable_exceptions as stage_exc:
        record_timeout_policy_failure(
            failures=failures,
            job_id=job_id,
            record=record,
            reason="stage_pre_execution_classification_failed",
            action="stage_pre_execution_classification_failed",
            error=stage_exc,
            source="inmemory_timeout_sweep.stage_is_pre_execution",
            pid=pid,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        stage_default, _stage_default_reason = scheduler_bool(None, default=False, reason="stage_pre_execution_default_rejected")
        return stage_default
    stage_default, _stage_default_reason = scheduler_bool(None, default=False, reason="stage_pre_execution_default_rejected")
    parsed, reason = scheduler_bool(
        value,
        default=stage_default,
        reason="stage_pre_execution_classification_return_rejected",
    )
    if reason:
        record_timeout_policy_failure(
            failures=failures,
            job_id=job_id,
            record=record,
            reason=reason,
            action="stage_pre_execution_classification_failed",
            error=ValueError(reason),
            source="inmemory_timeout_sweep.stage_is_pre_execution",
            pid=pid,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return stage_default
    return parsed


__all__ = (
    "record_timeout_policy_failure",
    "safe_record_float",
    "safe_stage_is_pre_execution",
    "safe_start_wait_budget",
    "safe_timeout_budget_number",
    "timeout_budget_for_record",
)
