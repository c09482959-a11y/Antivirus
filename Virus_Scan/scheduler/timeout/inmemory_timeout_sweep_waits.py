"""Queued and assigned start-wait timeout decisions for in-memory sweeps."""
from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_history_contract import (
    TimeoutHistoryTransitionRequest,
    replace_timeout_history_transition,
)

from typing import Callable, Mapping, MutableMapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_start_wait_decisions import (
    StartWaitDecision,
    StartWaitRecoveryFailureRequest,
    TimeoutRecoveryBoundary,
    record_start_wait_recovery_failure,
    start_wait_decision,
    timeout_record_field,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import (
    safe_record_float,
    safe_start_wait_budget,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_queued_wait import (
    evaluate_armed_queued_start_wait,
    evaluate_unarmed_queued_start_wait,
)


def evaluate_queued_start_wait(
    *,
    jid: object,
    rec: MutableMapping[str, object],
    now: float,
    recovery: TimeoutRecoveryBoundary,
    queued_unstarted_count: int,
    max_queued_unstarted: int,
    queued_start_timeout_sec: float,
    start_wait_budget: Callable[[Mapping[str, object], float], float],
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> StartWaitDecision:
    """Evaluate one queued record and return a replayable queued-wait decision."""

    armed_at = safe_record_float(
        record=rec,
        field="queued_timeout_armed_at",
        default=0.0,
        job_id=jid,
        pid=None,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    if not armed_at:
        return evaluate_unarmed_queued_start_wait(
            jid=jid,
            rec=rec,
            now=now,
            recovery=recovery,
            queued_unstarted_count=queued_unstarted_count,
            max_queued_unstarted=max_queued_unstarted,
            timeout_retry_evidence=timeout_retry_evidence,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    return evaluate_armed_queued_start_wait(
        jid=jid,
        rec=rec,
        now=now,
        armed_at=armed_at,
        recovery=recovery,
        queued_start_timeout_sec=queued_start_timeout_sec,
        start_wait_budget=start_wait_budget,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )


def evaluate_assigned_start_wait(
    *,
    jid: object,
    rec: MutableMapping[str, object],
    now: float,
    recovery: TimeoutRecoveryBoundary,
    assigned_start_timeout_sec: float,
    start_wait_budget: Callable[[Mapping[str, object], float], float],
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> StartWaitDecision:
    """Evaluate one assigned record and return a replayable assigned-wait decision."""

    assigned_at = safe_record_float(
        record=rec,
        field="assigned_at",
        default=0.0,
        job_id=jid,
        pid=timeout_record_field(rec, "pid").value,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    if not assigned_at:
        return start_wait_decision(wait_delta=0, state="missing_start_time", reason="assigned_start_wait_missing_assigned_at")
    if now - assigned_at <= safe_start_wait_budget(
        start_wait_budget=start_wait_budget,
        job_id=jid,
        record=rec,
        default_budget=assigned_start_timeout_sec,
        reason="assigned_start_wait_budget_failed",
        pid=timeout_record_field(rec, "pid").value,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    ):
        return start_wait_decision(wait_delta=0, state="within_budget", reason="assigned_start_wait_within_budget")
    try:
        updated = replace_timeout_history_transition(
            recovery,
            TimeoutHistoryTransitionRequest(
                job_id=jid,
                record=rec,
                reason="assigned_start_wait_no_retry",
                pid=timeout_record_field(rec, "pid").value,
                now=now,
                action="assigned_wait",
            ),
        )
        updated["assigned_at"] = now
    except recoverable_exceptions as recovery_exc:
        record_start_wait_recovery_failure(
            StartWaitRecoveryFailureRequest(
                    failures=timeout_retry_evidence,
                job_id=jid,
                record=rec,
                reason="assigned_start_wait_no_retry",
                pid=timeout_record_field(rec, "pid").value,
                action="assigned_wait_recovery_failed",
                error=recovery_exc,
                source="inmemory_timeout_sweep.replace_with_history_transition",
                record_scheduler_suppressed=record_scheduler_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            )
        )
    return start_wait_decision(wait_delta=1, state="transitioned_to_wait", reason="assigned_start_wait_no_retry")


__all__ = ("StartWaitDecision", "evaluate_assigned_start_wait", "evaluate_queued_start_wait")
