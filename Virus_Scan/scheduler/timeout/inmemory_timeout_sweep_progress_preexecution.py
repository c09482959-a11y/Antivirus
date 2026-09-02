"""Pre-execution progress-wait handling for in-memory timeout sweeps."""
from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_history_contract import (
    TimeoutHistoryTransitionRequest,
    replace_timeout_history_transition,
)

from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import record_timeout_recovery_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import safe_stage_is_pre_execution
from Virus_Scan.scheduler.timeout.inmemory_timeout_record_value_decisions import timeout_record_value_decision



def handle_pre_execution_progress_wait(
    *,
    jid: object,
    rec: Mapping[str, object],
    now: float,
    pid: object,
    budget_info: Mapping[str, object],
    recovery: object,
    stage_is_pre_execution: Callable[[str], bool],
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    """Record non-executable pre-execution progress waits without retrying."""

    stage_l = str.lower(
        scheduler_evidence_text(
            timeout_record_value_decision(rec, "stage").as_value(),
            missing_text="stage_missing",
            field_name="stage",
        )
    )
    executable_stage = any(
        token in stage_l
        for token in (
            "raw",
            "yara",
            "image",
            "media",
            "archive",
            "dotnet",
            "ilspy",
            "analyze",
            "binary",
        )
    )
    pre_execution_stage = safe_stage_is_pre_execution(
        classifier=stage_is_pre_execution,
        stage=stage_l,
        job_id=jid,
        record=rec,
        pid=pid,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    if executable_stage or not pre_execution_stage:
        return False
    try:
        updated = replace_timeout_history_transition(
            recovery,
            TimeoutHistoryTransitionRequest(
                job_id=jid,
                record=rec,
                reason="pre_execution_progress_wait_no_retry",
                pid=pid,
                now=now,
                action="pre_execution_wait",
                extra={"stage": stage_l},
            ),
        )
        updated["last_progress_time"] = now
    except recoverable_exceptions as recovery_exc:
        record_timeout_recovery_failure(
            failures=timeout_retry_evidence,
            job_id=jid,
            reason="pre_execution_progress_wait_no_retry",
            pid=pid,
            action="pre_execution_wait_recovery_failed",
            attempt=timeout_record_value_decision(rec, "attempt").as_value(),
            timeout_budget=budget_info,
            error=recovery_exc,
            source="inmemory_timeout_sweep.replace_with_history_transition",
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    return True


__all__ = ("handle_pre_execution_progress_wait",)
