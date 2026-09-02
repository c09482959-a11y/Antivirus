"""Queued start-wait timeout transition helpers for in-memory sweeps."""
from __future__ import annotations

from typing import Callable, Mapping, MutableMapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_history_contract import (
    TimeoutHistoryTransitionRequest,
    replace_timeout_history_transition,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_start_wait_decisions import (
    StartWaitDecision,
    StartWaitRecoveryFailureRequest,
    TimeoutRecoveryBoundary,
    record_start_wait_recovery_failure,
    start_wait_decision,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import safe_start_wait_budget


def evaluate_unarmed_queued_start_wait(
    *,
    jid: object,
    rec: MutableMapping[str, object],
    now: float,
    recovery: TimeoutRecoveryBoundary,
    queued_unstarted_count: int,
    max_queued_unstarted: int,
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> StartWaitDecision:
    """Arm queued timeout tracking or transition when the backlog cushion is full."""
    if queued_unstarted_count < max_queued_unstarted:
        rec["queued_timeout_armed_at"] = now
        return start_wait_decision(wait_delta=0, state="not_armed_backlog_available", reason="queued_timeout_armed")
    try:
        replace_timeout_history_transition(
            recovery,
            TimeoutHistoryTransitionRequest(
                job_id=jid,
                record=rec,
                reason="queued_timeout_not_armed_backlog_cushion_full",
                pid=None,
                now=now,
                action="queued_wait",
            ),
        )
    except recoverable_exceptions as recovery_exc:
        record_start_wait_recovery_failure(
            StartWaitRecoveryFailureRequest(
                failures=timeout_retry_evidence,
                job_id=jid,
                record=rec,
                reason="queued_timeout_not_armed_backlog_cushion_full",
                pid=None,
                action="queued_wait_recovery_failed",
                error=recovery_exc,
                source="inmemory_timeout_sweep.replace_with_history_transition",
                record_scheduler_suppressed=record_scheduler_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            )
        )
    return start_wait_decision(
        wait_delta=1,
        state="not_armed_backlog_full",
        reason="queued_timeout_not_armed_backlog_cushion_full",
    )


def evaluate_armed_queued_start_wait(
    *,
    jid: object,
    rec: MutableMapping[str, object],
    now: float,
    armed_at: float,
    recovery: TimeoutRecoveryBoundary,
    queued_start_timeout_sec: float,
    start_wait_budget: Callable[[Mapping[str, object], float], float],
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> StartWaitDecision:
    """Transition a queued record whose armed wait exceeded its safe budget."""
    if now - armed_at <= safe_start_wait_budget(
        start_wait_budget=start_wait_budget,
        job_id=jid,
        record=rec,
        default_budget=queued_start_timeout_sec,
        reason="queued_start_wait_budget_failed",
        pid=None,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    ):
        return start_wait_decision(wait_delta=0, state="within_budget", reason="queued_start_wait_within_budget")
    try:
        updated = replace_timeout_history_transition(
            recovery,
            TimeoutHistoryTransitionRequest(
                job_id=jid,
                record=rec,
                reason="queued_start_wait_no_retry",
                pid=None,
                now=now,
                action="queued_wait",
            ),
        )
        updated["queued_timeout_armed_at"] = now
    except recoverable_exceptions as recovery_exc:
        record_start_wait_recovery_failure(
            StartWaitRecoveryFailureRequest(
                failures=timeout_retry_evidence,
                job_id=jid,
                record=rec,
                reason="queued_start_wait_no_retry",
                pid=None,
                action="queued_wait_recovery_failed",
                error=recovery_exc,
                source="inmemory_timeout_sweep.replace_with_history_transition",
                record_scheduler_suppressed=record_scheduler_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            )
        )
    return start_wait_decision(wait_delta=1, state="transitioned_to_wait", reason="queued_start_wait_no_retry")


__all__ = ("evaluate_armed_queued_start_wait", "evaluate_unarmed_queued_start_wait")
