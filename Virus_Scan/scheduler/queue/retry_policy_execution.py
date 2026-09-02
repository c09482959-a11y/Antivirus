"""Support helpers for queue-owned file retry execution."""
from __future__ import annotations

from collections.abc import Callable, Mapping

from Virus_Scan.scheduler.queue.retry_integrity_persistence import RetryIntegrityPersistenceFailureRequest
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.api.contracts import QueueRetryPolicyError
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_exception_text,
)
from Virus_Scan.scheduler.queue.retry_integrity_evidence import retry_integrity_clear_evidence
from Virus_Scan.scheduler.queue.retry_policy_callback_safety import (
    RETRY_POLICY_EXCEPTIONS,
    record_retry_policy_callback_failure,
)


def run_retry_worker_attempt(
    *,
    worker_once: Callable[..., object],
    path: object,
    prev: object,
    use_signal_timeout: bool,
    attempt: int,
    retry_failures: list[dict[str, object]],
) -> tuple[object, object]:
    """Run one retry worker attempt and project worker callback failures."""
    try:
        return worker_once(path, prev, use_signal_timeout)
    except RETRY_POLICY_EXCEPTIONS as exc:
        evidence = record_retry_policy_callback_failure(
            retry_failures=retry_failures,
            path=path,
            attempt=attempt,
            callback_name="worker_once",
            error=exc,
        )
        return path, {
            "error": scheduler_exception_text(exc),
            "exception_type": no_hook_type_name(exc),
            "scan_integrity": {
                **evidence.as_scan_integrity(),
                "file_failed": True,
                "allow_learning": False,
            },
        }


def clear_retry_integrity_for_next_attempt(
    *,
    clear_integrity: Callable[[object], object],
    report_retry_log_failure: Callable[[BaseException, Mapping[str, object]], object],
    retry_log_failure_reporter: Callable[..., object],
    path: object,
    attempt: int,
    retry_failures: list[dict[str, object]],
) -> None:
    """Clear retry integrity and preserve cleanup failures as replay evidence."""
    try:
        clear_integrity(path)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        failure = QueueRetryPolicyError(
            "retry integrity clear failed for "
            + scheduler_evidence_path(path, field_name="retry_path")
            + ": "
            + scheduler_exception_text(exc)
        )
        clear_evidence = retry_integrity_clear_evidence(path=path, attempt=attempt, error=failure)
        retry_failures.append(clear_evidence.as_record())
        retry_log_failure_reporter(
            retry_failures=retry_failures,
            path=path,
            attempt=attempt,
            original_error=failure,
            report_retry_log_failure=report_retry_log_failure,
        )


def apply_retry_failure_integrity(
    *,
    integrity: dict[str, object],
    retry_failures: list[dict[str, object]],
) -> None:
    """Apply accumulated retry failure records to the final integrity mapping."""
    if not retry_failures:
        return
    integrity["file_retry_integrity_clear_failed"] = True
    integrity["file_retry_failures"] = tuple(retry_failures)
    if any(record.get("stage") == "queue_retry_log_publication" for record in retry_failures if isinstance(record, Mapping)):
        integrity["queue_retry_log_publication_failed"] = True
        integrity["queue_failure"] = True
        integrity["had_degraded_stage"] = True
        integrity["allow_learning"] = False
    if any(record.get("stage") == "queue_retry_policy_callback" for record in retry_failures if isinstance(record, Mapping)):
        integrity["queue_retry_policy_callback_failed"] = True
        integrity["queue_failure"] = True
        integrity["had_degraded_stage"] = True
        integrity["allow_learning"] = False
    if any(record.get("stage") == "queue_retry_integrity_clear" for record in retry_failures if isinstance(record, Mapping)):
        integrity["queue_retry_integrity_clear_failed"] = True
        integrity["queue_failure"] = True
        integrity["had_degraded_stage"] = True
        integrity["allow_learning"] = False


def persist_retry_integrity(
    *,
    set_integrity: Callable[[object, Mapping[str, object]], object],
    report_retry_log_failure: Callable[[BaseException, Mapping[str, object]], object],
    persistence_failure_recorder: Callable[[RetryIntegrityPersistenceFailureRequest], object],
    result: dict[str, object],
    integrity: dict[str, object],
    path: object,
    attempt: int,
) -> None:
    """Persist final retry integrity while recording persistence failures."""
    try:
        set_integrity(path, integrity)
    except RETRY_POLICY_EXCEPTIONS as exc:
        persistence_failure_recorder(
            RetryIntegrityPersistenceFailureRequest(
                result=result,
                integrity=integrity,
                path=path,
                attempt=attempt,
                error=exc,
                report_retry_log_failure=report_retry_log_failure,
            )
        )
        result["scan_integrity"] = integrity


__all__ = (
    "apply_retry_failure_integrity",
    "clear_retry_integrity_for_next_attempt",
    "persist_retry_integrity",
    "run_retry_worker_attempt",
)
