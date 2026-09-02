"""Queue-owned retry integrity persistence failure handling."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path
from Virus_Scan.scheduler.queue.retry_integrity_evidence import (
    retry_integrity_persistence_evidence,
    retry_integrity_persistence_report_evidence,
)
from Virus_Scan.scheduler.queue.retry_policy_callback_safety import (
    RETRY_POLICY_EXCEPTIONS,
    retry_policy_callback_error,
    retry_policy_callback_supported,
)


@dataclass(frozen=True, slots=True)
class RetryIntegrityPersistenceFailureRequest:
    result: dict[str, object]
    integrity: dict[str, object]
    path: object
    attempt: int
    error: BaseException
    report_retry_log_failure: Callable[[BaseException, Mapping[str, object]], object]


def record_retry_integrity_persistence_failure(
    request: RetryIntegrityPersistenceFailureRequest,
) -> None:
    safe_attempt, attempt_reason = no_hook_exact_nonnegative_int(
        request.attempt,
        reason="retry_integrity_persistence_attempt_rejected",
    )
    report_error = request.error if not attempt_reason else ValueError(attempt_reason)
    evidence = retry_integrity_persistence_evidence(path=request.path, attempt=safe_attempt, error=report_error)
    evidence_record = evidence.as_record()
    request.integrity.update(evidence.as_scan_integrity())
    failures = tuple(dict.get(request.integrity, "queue_retry_integrity_persistence_failures") or ())
    request.integrity["queue_retry_integrity_persistence_failures"] = (*failures, evidence_record)
    request.result["queue_retry_integrity_persistence_failed"] = True
    request.result["queue_retry_integrity_persistence_evidence"] = evidence_record
    report_exc: BaseException | None = None
    if retry_policy_callback_supported(request.report_retry_log_failure):
        try:
            request.report_retry_log_failure(
                report_error,
                {
                    "file": scheduler_evidence_path(request.path, field_name="retry_path"),
                    "attempt": safe_attempt,
                    "stage": "queue_retry_integrity_persistence",
                },
            )
        except RETRY_POLICY_EXCEPTIONS as exc:
            report_exc = exc
    else:
        report_exc = retry_policy_callback_error(request.report_retry_log_failure, "report_retry_log_failure")
    if report_exc is not None:
        report_evidence = retry_integrity_persistence_report_evidence(
            path=request.path,
            attempt=safe_attempt,
            error=report_exc,
            original_error=report_error,
        )
        request.integrity.update(report_evidence.as_scan_integrity())



__all__ = (
    'RetryIntegrityPersistenceFailureRequest',
    'record_retry_integrity_persistence_failure',
)
