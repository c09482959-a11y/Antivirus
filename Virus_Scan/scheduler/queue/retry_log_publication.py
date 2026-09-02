"""Queue-owned retry log publication failure handling."""
from __future__ import annotations

from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path
from Virus_Scan.scheduler.queue.retry_policy_callback_safety import (
    RETRY_POLICY_EXCEPTIONS,
    retry_policy_callback_error,
    retry_policy_callback_supported,
)
from Virus_Scan.scheduler.queue.retry_publication_evidence import retry_log_publication_evidence


def safe_report_retry_log_failure(
    *,
    retry_failures: list[dict[str, object]],
    path: object,
    attempt: int,
    original_error: BaseException,
    report_retry_log_failure: Callable[[BaseException, Mapping[str, object]], object],
) -> None:
    safe_attempt, attempt_reason = no_hook_exact_nonnegative_int(
        attempt,
        reason="retry_log_publication_attempt_rejected",
    )
    report_error = original_error if not attempt_reason else ValueError(attempt_reason)
    report_exc: BaseException | None = None
    if retry_policy_callback_supported(report_retry_log_failure):
        try:
            report_retry_log_failure(
                report_error,
                {
                    "file": scheduler_evidence_path(path, field_name="retry_path"),
                    "attempt": safe_attempt,
                },
            )
        except RETRY_POLICY_EXCEPTIONS as exc:
            report_exc = exc
    else:
        report_exc = retry_policy_callback_error(report_retry_log_failure, "report_retry_log_failure")
    if report_exc is not None:
        evidence = retry_log_publication_evidence(
            path=path,
            attempt=safe_attempt,
            error=report_exc,
            original_error=report_error,
        )
        retry_failures.append(evidence.as_record())


__all__ = ("safe_report_retry_log_failure",)
