"""Immutable timeout/retry/escalation evidence for in-memory scheduler sweeps."""
from __future__ import annotations

from types import MappingProxyType
from typing import Callable, Mapping, TypeAlias

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_text,
    scheduler_exception_text,
    scheduler_int,
)
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence

TimeoutEvidenceRecord: TypeAlias = Mapping[str, object]
TimeoutMutableEvidenceRecord: TypeAlias = dict[str, object]
TimeoutBudget: TypeAlias = Mapping[str, object]
TimeoutSuppressionRecorder: TypeAlias = Callable[[str, BaseException], object]



def _timeout_int_field(value: object, *, field_name: str) -> object:
    safe_field = scheduler_evidence_text(
        field_name,
        missing_text="timeout_field",
        field_name="timeout_field",
    )
    parsed, reason = scheduler_int(value, default=0, reason="unsafe_" + safe_field + "_rejected")
    if reason:
        return unsupported_scheduler_value_evidence(value, field_name=safe_field)
    return parsed


def _timeout_identity_field(value: object, *, field_name: str) -> object:
    if type(value) is str:
        return str.__str__(value)
    return _timeout_int_field(value, field_name=field_name)


def timeout_retry_evidence(
    *,
    job_id: object,
    reason: str,
    pid: object,
    action: str,
    attempt: object,
    timeout_budget: TimeoutBudget | None = None,
    error_category: str | None = None,
    error_source: str | None = None,
    detail: str | None = None,
) -> TimeoutEvidenceRecord:
    record: TimeoutMutableEvidenceRecord = {
        "stage": "inmemory_timeout_retry_escalation",
        "job_id": _timeout_identity_field(job_id, field_name="timeout_job_id"),
        "reason": scheduler_evidence_text(reason, missing_text="timeout_retry", field_name="timeout_reason"),
        "pid": _timeout_identity_field(pid, field_name="timeout_worker_pid"),
        "action": scheduler_evidence_text(action, missing_text="timeout_retry", field_name="timeout_action"),
        "attempt": _timeout_int_field(attempt, field_name="timeout_attempt"),
        "timeout_budget": materialize_scheduler_mapping(timeout_budget if timeout_budget is not None else {}),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_reproduce": True,
    }
    if error_category is not None:
        record["error_category"] = scheduler_evidence_text(
            error_category,
            missing_text="timeout_error",
            field_name="timeout_error_category",
        )
    if error_source is not None:
        record["error_source"] = scheduler_evidence_text(
            error_source,
            missing_text="scheduler.timeout",
            field_name="timeout_error_source",
        )
    if detail is not None:
        record["detail"] = scheduler_evidence_text(
            detail,
            missing_text="timeout detail unavailable",
            field_name="timeout_detail",
        )[:1000]
    return MappingProxyType(record)


def timeout_reporting_failure(*, job_id: object, reason: str, error: BaseException) -> TimeoutEvidenceRecord:
    return MappingProxyType(
        {
            "stage": "inmemory_timeout_reporting",
            "job_id": _timeout_identity_field(job_id, field_name="timeout_job_id"),
            "reason": scheduler_evidence_text(
                reason,
                missing_text="timeout_reporting_failed",
                field_name="timeout_reason",
            ),
            "error_category": no_hook_type_name(error),
            "detail": scheduler_exception_text(error),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_reproduce": True,
        }
    )


def timeout_recovery_failure_evidence(
    *,
    job_id: object,
    reason: str,
    pid: object,
    action: str,
    attempt: object,
    timeout_budget: TimeoutBudget | None,
    error: BaseException,
    source: str,
) -> TimeoutEvidenceRecord:
    return timeout_retry_evidence(
        job_id=job_id,
        reason=reason,
        pid=pid,
        action=action,
        attempt=attempt,
        timeout_budget=timeout_budget,
        error_category=no_hook_type_name(error),
        error_source=source,
        detail=scheduler_exception_text(error),
    )


def record_timeout_recovery_failure(
    *,
    failures: list[TimeoutEvidenceRecord],
    job_id: object,
    reason: str,
    pid: object,
    action: str,
    attempt: object,
    timeout_budget: TimeoutBudget | None,
    error: BaseException,
    source: str,
    record_scheduler_suppressed: TimeoutSuppressionRecorder,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    detail_error: BaseException = error
    try:
        record_scheduler_suppressed("suppressed_exception", error)
    except recoverable_exceptions as record_exc:
        detail_error = RuntimeError(
            scheduler_exception_text(error)
            + "; suppression_record_failed="
            + scheduler_exception_text(record_exc)
        )
    failures.append(
        timeout_recovery_failure_evidence(
            job_id=job_id,
            reason=reason,
            pid=pid,
            action=action,
            attempt=attempt,
            timeout_budget=timeout_budget,
            error=detail_error,
            source=source,
        )
    )


__all__ = (
    "record_timeout_recovery_failure",
    "timeout_recovery_failure_evidence",
    "timeout_reporting_failure",
    "timeout_retry_evidence",
)
