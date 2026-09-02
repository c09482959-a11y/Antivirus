"""Bounded running timeout transition steps for in-memory timeout sweeps."""
from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_history_contract import (
    TimeoutHistoryTransitionRequest,
    replace_timeout_history_transition,
)

from typing import Callable, Mapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import record_timeout_recovery_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_record_value_decisions import timeout_record_value_decision
from Virus_Scan.scheduler.timeout import inmemory_timeout_retry_actions as retry_actions
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_contracts import RunningProgressStallRequest
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_progress import evaluate_running_progress_stall


def record_running_hard_timeout(
    *,
    jid: object,
    rec: Mapping[str, object],
    now: float,
    pid: object,
    recovery: object,
    budget_info: Mapping[str, object],
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Record hard-timeout history and retry/fail escalation evidence."""
    try:
        replace_timeout_history_transition(
            recovery,
            TimeoutHistoryTransitionRequest(
                job_id=jid,
                record=rec,
                reason="queue_worker_hard_timeout",
                pid=pid,
                now=now,
                action="hard_timeout",
                extra={"timeout_budget": budget_info},
            ),
        )
    except recoverable_exceptions as recovery_exc:
        record_timeout_recovery_failure(
            failures=timeout_retry_evidence,
            job_id=jid,
            reason="queue_worker_hard_timeout",
            pid=pid,
            action="hard_timeout_history_failed",
            attempt=timeout_record_value_decision(rec, "attempt").as_value(),
            timeout_budget=budget_info,
            error=recovery_exc,
            source="inmemory_timeout_sweep.replace_with_history_transition",
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    retry_actions.record_retry_or_fail_escalation(
        retry_actions.RetryOrFailEscalationRequest(
            recovery=recovery,
            failures=timeout_retry_evidence,
            job_id=jid,
            reason="queue_worker_hard_timeout",
            pid=pid,
            attempt=timeout_record_value_decision(rec, "attempt").as_value(),
            timeout_budget=budget_info,
            source="inmemory_timeout_sweep.retry_or_fail",
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    )


def record_running_orphaned_worker(
    *,
    jid: object,
    rec: Mapping[str, object],
    pid: object,
    recovery: object,
    budget_info: Mapping[str, object],
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Record orphaned-worker retry/fail escalation evidence."""
    retry_actions.record_retry_or_fail_escalation(
        retry_actions.RetryOrFailEscalationRequest(
            recovery=recovery,
            failures=timeout_retry_evidence,
            job_id=jid,
            reason="queue_worker_orphaned",
            pid=pid,
            attempt=timeout_record_value_decision(rec, "attempt").as_value(),
            timeout_budget=budget_info,
            source="inmemory_timeout_sweep.retry_or_fail",
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    )


def evaluate_running_timeout_transition(
    *,
    jid: object,
    rec: Mapping[str, object],
    now: float,
    recovery: object,
    state: object,
    cancel_grace_sec: float,
    stage_is_pre_execution: Callable[[str], bool],
    update_ewma: Callable[..., object],
    ewma_state: dict[str, object],
    timeout_retry_evidence: list[Mapping[str, object]],
    timeout_reporting_failures: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[int, int, int, int]:
    """Evaluate timeout state against hard/orphan/progress-stall decisions."""
    if state.pid and state.running_at and ((now - state.running_at) > state.hard_budget):
        record_running_hard_timeout(
            jid=jid,
            rec=rec,
            now=now,
            pid=state.pid,
            recovery=recovery,
            budget_info=state.budget_info,
            timeout_retry_evidence=timeout_retry_evidence,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return 1, 0, 0, 0
    if state.pid and state.last_heartbeat and (state.heartbeat_age > state.heartbeat_budget):
        record_running_orphaned_worker(
            jid=jid,
            rec=rec,
            pid=state.pid,
            recovery=recovery,
            budget_info=state.budget_info,
            timeout_retry_evidence=timeout_retry_evidence,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return 0, 1, 0, 0
    if state.pid and state.last_progress and (state.progress_age > state.progress_budget):
        progress_stalls, cancelled_after_stall = evaluate_running_progress_stall(
            RunningProgressStallRequest(
                jid=jid,
                rec=rec,
                now=now,
                pid=state.pid,
                progress_age=state.progress_age,
                budget_info=state.budget_info,
                recovery=recovery,
                cancel_grace_sec=cancel_grace_sec,
                stage_is_pre_execution=stage_is_pre_execution,
                update_ewma=update_ewma,
                ewma_state=ewma_state,
                timeout_retry_evidence=timeout_retry_evidence,
                timeout_reporting_failures=timeout_reporting_failures,
                record_scheduler_suppressed=record_scheduler_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            )
        )
        return 0, 0, progress_stalls, cancelled_after_stall
    return 0, 0, 0, 0


__all__ = (
    "evaluate_running_timeout_transition",
    "record_running_hard_timeout",
    "record_running_orphaned_worker",
)
