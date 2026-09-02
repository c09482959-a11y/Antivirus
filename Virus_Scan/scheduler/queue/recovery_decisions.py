"""Canonical scheduler recovery-decision ownership.

This module owns immutable recovery classification and worker failure accounting.
It does not execute scanner work or mutate queue directories.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_file_identity_for_path as _queue_file_identity_for_path
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.runtime.api import observe_runtime_economics
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.queue.recovery_contracts import QueueRecoveryDecision, QueueWorkerFailureAccounting
from Virus_Scan.scheduler.queue.retry_recovery_decisions import scheduler_recovery_record_decision, scheduler_recovery_text_decision



_SCHEDULER_JOB_IDENTITY_MISSING = "scheduler job identity missing"
_SCHEDULER_JOB_IDENTITY_MISSING_FILE_PATH = "scheduler job identity missing file path"
_SCHEDULER_JOB_PATH_MISSING = "scheduler job path missing"


def _raise_scheduler_job_identity_missing() -> NoReturn:
    raise RuntimeError(_SCHEDULER_JOB_IDENTITY_MISSING)


@dataclass(frozen=True)
class RecoveryDecision:
    action: str
    reason: str
    retryable: bool = False


def classify_queue_failure(error: BaseException | str, *, stage: str = "process_queue") -> RecoveryDecision:
    if isinstance(error, BaseException):
        text = scheduler_exception_text(error, missing_text="scheduler_queue_failure_unavailable").lower()
    else:
        text = scheduler_recovery_text_decision(error).as_text().lower()
    retryable = any(word in text for word in ("timeout", "temporar", "permission", "access is denied", "worker", "queue"))
    decision = RecoveryDecision("retry" if retryable else "quarantine", "scheduler.queue", retryable)
    try:
        observe_runtime_economics("recovery_cost", 1.0 if decision.retryable else 2.0)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure("recovery_authorize_failed", exc, domain="scheduler")
    stage_text = scheduler_recovery_text_decision(stage).as_text() or "process_queue"
    return RecoveryDecision(decision.action, stage_text + ":" + decision.reason, decision.retryable)


def classify_recovery_decision(job: object, worker_state: object, failure_reason: object) -> object:
    """Return the one canonical scheduler recovery decision for a failed job."""
    job_record = scheduler_recovery_record_decision(job).as_mapping()
    worker_record = scheduler_recovery_record_decision(worker_state).as_mapping()
    if not job_record:
        _raise_scheduler_job_identity_missing()
    job_id = ""
    for key in ("job_id", "id", "queue_id", "raw_job_id"):
        value = scheduler_recovery_text_decision(job_record.get(key)).as_text()
        if value:
            job_id = value
            break
    file_path = (
        scheduler_recovery_text_decision(job_record.get("file")).as_text()
        or scheduler_recovery_text_decision(job_record.get("path")).as_text()
    )
    if not job_id:
        if file_path:
            job_id = _queue_file_identity_for_path(file_path)
        else:
            raise RuntimeError(_SCHEDULER_JOB_IDENTITY_MISSING_FILE_PATH)
    if not file_path:
        raise RuntimeError(_SCHEDULER_JOB_PATH_MISSING)
    worker_id = (
        scheduler_recovery_text_decision(worker_record.get("worker_id")).as_text()
        or scheduler_recovery_text_decision(worker_record.get("pid")).as_text()
        or scheduler_recovery_text_decision(job_record.get("worker_id")).as_text()
        or "unknown"
    )
    raw_attempt = job_record.get("attempt") if job_record.get("attempt") is not None else worker_record.get("attempt")
    attempt_count, _attempt_reason = scheduler_int(raw_attempt, default=0, minimum=0)
    max_attempts = 1
    for owner in (worker_record, job_record):
        value = owner.get("max_attempts")
        if value is not None:
            max_attempts, _max_attempts_reason = scheduler_int(value, default=0, minimum=0)
            break
    reason = (
        scheduler_recovery_text_decision(failure_reason).as_text()
        or scheduler_recovery_text_decision(worker_record.get("failure_reason")).as_text()
        or "worker_failure"
    )
    normalized = reason.lower()
    if "quarantine" in normalized or "malformed" in normalized or "invalid" in normalized:
        action = "quarantine"
    elif attempt_count < max_attempts and "missing" not in normalized and "not found" not in normalized:
        action = "requeue"
    else:
        action = "fail"
    decision = QueueRecoveryDecision(
        job_id=job_id,
        worker_id=worker_id,
        file_path=file_path,
        failure_reason=reason,
        final_action=action,
        reason_text=action + ":" + reason,
        attempt_count=attempt_count,
        source_event=(
            scheduler_recovery_text_decision(worker_record.get("source_event")).as_text()
            or scheduler_recovery_text_decision(worker_record.get("event")).as_text()
            or "scheduler_recovery"
        ),
    )
    decision.assert_valid()
    return decision


def _record_worker_failure_accounting(job: object, worker_state: object, failure_reason: object) -> object:
    """Create immutable timeout/kill accounting from the canonical recovery decision."""
    decision = classify_recovery_decision(job, worker_state, failure_reason)
    accounting = QueueWorkerFailureAccounting(
        worker_id=decision.worker_id,
        job_id=decision.job_id,
        file_path=decision.file_path,
        failure_reason=decision.failure_reason,
        requeued=decision.final_action == "requeue",
        failed=decision.final_action in {"fail", "quarantine"},
        attempt_count=decision.attempt_count,
        final_scheduler_action=decision.final_action,
    )
    accounting.assert_valid()
    return accounting
