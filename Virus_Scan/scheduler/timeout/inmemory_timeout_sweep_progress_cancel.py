"""Progress-stall cancellation and escalation decisions."""
from __future__ import annotations

import logging
from typing import Callable, Mapping, Protocol, TypeAlias

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text, scheduler_float
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import (
    record_timeout_recovery_failure,
    timeout_reporting_failure,
    timeout_retry_evidence as build_timeout_retry_evidence,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_numeric_policy import safe_timeout_policy_number
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import safe_record_float
from Virus_Scan.scheduler.timeout import inmemory_timeout_retry_actions as retry_actions
from Virus_Scan.scheduler.timeout.inmemory_timeout_record_value_decisions import timeout_record_value_decision

TimeoutRecord: TypeAlias = Mapping[str, object]
TimeoutEvidenceRecord: TypeAlias = Mapping[str, object]
TimeoutEvidenceList: TypeAlias = list[TimeoutEvidenceRecord]
EwmaState: TypeAlias = dict[str, object]
SuppressionRecorder: TypeAlias = Callable[[str, BaseException], object]


class ProgressStallRecovery(Protocol):
    def request_cancel_only(self, job_id: object, reason: str, *, pid: object | None = None) -> object: ...
    def retry_or_fail(self, job_id: object, reason: str, *, pid: object | None = None) -> object: ...
    def retry_evidence_count(self) -> int: ...
    def retry_evidence_since(self, cursor: object) -> tuple[Mapping[str, object], ...]: ...
    def cancel_evidence_count(self) -> int: ...
    def cancel_evidence_since(self, cursor: object) -> tuple[Mapping[str, object], ...]: ...

class EwmaUpdater(Protocol):
    def __call__(self, metric: str, value: float, *, state: EwmaState) -> object: ...

def evaluate_progress_stall_cancellation(
    *,
    jid: object,
    rec: TimeoutRecord,
    now: float,
    pid: object,
    progress_age: float,
    budget_info: TimeoutRecord,
    recovery: ProgressStallRecovery,
    cancel_grace_sec: float,
    update_ewma: EwmaUpdater,
    ewma_state: EwmaState,
    timeout_retry_evidence: TimeoutEvidenceList,
    timeout_reporting_failures: TimeoutEvidenceList,
    record_scheduler_suppressed: SuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[int, int]:
    cancel_at = safe_record_float(
        record=rec,
        field="cancel_requested_at",
        default=0.0,
        job_id=jid,
        pid=pid,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    if not cancel_at:
        record_progress_stall_cancel(
            jid=jid,
            rec=rec,
            pid=pid,
            progress_age=progress_age,
            budget_info=budget_info,
            recovery=recovery,
            update_ewma=update_ewma,
            ewma_state=ewma_state,
            timeout_retry_evidence=timeout_retry_evidence,
            timeout_reporting_failures=timeout_reporting_failures,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return 1, 0
    grace = safe_timeout_policy_number(
        value=cancel_grace_sec,
        default=0.0,
        field="cancel_grace_sec",
        job_id=jid,
        record=rec,
        pid=pid,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    if now - cancel_at > grace:
        retry_actions.record_retry_or_fail_escalation(
            retry_actions.RetryOrFailEscalationRequest(
                recovery=recovery,
                failures=timeout_retry_evidence,
                job_id=jid,
                reason="queue_worker_killed_after_stall",
                pid=pid,
                attempt=timeout_record_value_decision(rec, "attempt").as_value(),
                timeout_budget=budget_info,
                source="inmemory_timeout_sweep.retry_or_fail",
                record_scheduler_suppressed=record_scheduler_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            ))
        return 0, 1
    return 0, 0


def record_progress_stall_cancel(
    *,
    jid: object,
    rec: TimeoutRecord,
    pid: object,
    progress_age: float,
    budget_info: TimeoutRecord,
    recovery: ProgressStallRecovery,
    update_ewma: EwmaUpdater,
    ewma_state: EwmaState,
    timeout_retry_evidence: TimeoutEvidenceList,
    timeout_reporting_failures: TimeoutEvidenceList,
    record_scheduler_suppressed: SuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    progress_age_value, _progress_age_reason = scheduler_float(
        progress_age,
        default=0.0,
        reason="progress_age_rejected",
    )
    try:
        logging.warning(
            "in-memory scheduler progress stall: job_id="
            + scheduler_evidence_text(jid, missing_text="job_id", field_name="job_id")
            + " attempt="
            + scheduler_evidence_text(
                timeout_record_value_decision(rec, "attempt").as_value(),
                missing_text="attempt_missing",
                field_name="attempt",
            )
            + " stage="
            + scheduler_evidence_text(
                timeout_record_value_decision(rec, "stage").as_value(),
                missing_text="stage_missing",
                field_name="stage",
            )
            + " no_progress="
            + float.__format__(progress_age_value, ".1f")
            + "s file="
            + scheduler_evidence_text(
                timeout_record_value_decision(rec, "file").as_value(),
                missing_text="file_missing",
                field_name="file",
            )
        )
        update_ewma("heartbeat_stalls", 1.0, state=ewma_state)
    except recoverable_exceptions as suppressed_exc:
        timeout_reporting_failures.append(
            timeout_reporting_failure(job_id=jid, reason="progress_stall_reporting_failed", error=suppressed_exc)
        )
        try:
            record_scheduler_suppressed("suppressed_exception", suppressed_exc)
        except recoverable_exceptions as record_exc:
            timeout_reporting_failures.append(
                timeout_reporting_failure(job_id=jid, reason="progress_stall_reporting_suppression_failed", error=record_exc)
            )
    cancel_evidence_count = recovery.cancel_evidence_count()
    try:
        recovery.request_cancel_only(jid, "queue_worker_progress_stalled", pid=pid)
    except recoverable_exceptions as recovery_exc:
        record_timeout_recovery_failure(
            failures=timeout_retry_evidence,
            job_id=jid,
            reason="queue_worker_progress_stalled",
            pid=pid,
            action="cancel_only_failed",
            attempt=timeout_record_value_decision(rec, "attempt").as_value(),
            timeout_budget=budget_info,
            error=recovery_exc,
            source="inmemory_timeout_sweep.request_cancel_only",
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
    timeout_retry_evidence.extend(recovery.cancel_evidence_since(cancel_evidence_count))
    timeout_retry_evidence.append(
        build_timeout_retry_evidence(
            job_id=jid,
            reason="queue_worker_progress_stalled",
            pid=pid,
            action="cancel_only",
            attempt=timeout_record_value_decision(rec, "attempt").as_value(),
            timeout_budget=budget_info,
        )
    )


__all__ = (
    "EwmaUpdater",
    "ProgressStallRecovery",
    "evaluate_progress_stall_cancellation",
    "record_progress_stall_cancel",
)
