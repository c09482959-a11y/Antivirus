"""Scheduler-owned worker result contracts."""
from __future__ import annotations



from Virus_Scan.contracts.result_record import make_worker_error_result
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.internal.worker_result_boundary import (
    WorkerResultNormalizationEvidence,
    build_worker_result_schema_failure,
    scheduler_exception_text,
    scheduler_owned_mapping_snapshot,
    scheduler_scan_integrity_snapshot,
    scheduler_path_text,
    scheduler_reason_text,
)


def make_scheduler_worker_error_result(path: object, exc: BaseException | str) -> dict[str, object]:
    """Return the canonical scheduler worker error record."""
    return make_worker_error_result(path, exc)


def make_scheduler_cancel_result(path: object, reason: str = "cancelled_generation") -> tuple[object, dict[str, object]]:
    """Return a scheduler-owned cancellation result tuple for worker queues."""
    safe_path, _path_reason = scheduler_path_text(path)
    safe_reason, _reason_unavailable = scheduler_reason_text(reason, replacement_text="cancelled_generation")
    try:
        result = make_scheduler_worker_error_result(safe_path, RuntimeError(safe_reason))
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        error_text = scheduler_exception_text(exc)
        result = make_worker_error_result(
            safe_path,
            RuntimeError(
                str.__add__(
                    str.__add__(safe_reason, "; cancel-result constructor failed: "),
                    error_text,
                )
            ),
        )
    try:
        result["queue_failure"] = True
        result["scheduler_failure_reason"] = safe_reason
        result["cancelled_generation"] = True
    except RECOVERABLE_RUNTIME_ERRORS as annotate_exc:
        try:
            record_suppressed_failure("scheduler_cancel_result_annotation_failed", annotate_exc, domain="scheduler")
        except RECOVERABLE_RUNTIME_ERRORS as report_exc:
            _ = report_exc
    return safe_path, result


def normalize_scheduler_worker_result(
    path: object,
    result: object,
    *,
    worker_error_result: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
    reason: str = "invalid_worker_result_schema",
) -> dict[str, object]:
    """Validate and normalize one worker result before queue publication."""
    normalized = scheduler_owned_mapping_snapshot(result)
    if normalized is None:
        return build_worker_result_schema_failure(
            path,
            result,
            worker_error_result=worker_error_result,
            recoverable_exceptions=recoverable_exceptions,
            reason=reason,
        )
    integrity = dict.get(normalized, "scan_integrity")
    if integrity is not None:
        normalized["scan_integrity"] = scheduler_scan_integrity_snapshot(
            integrity,
            unavailable_reason="non_materializable_worker_result_integrity",
            original_type_field="worker_result_integrity_original_type",
            unavailable_flag="worker_result_integrity_unavailable",
            unavailable_reason_field="worker_result_integrity_unavailable_reason",
        )
    return normalized


__all__ = (
    "WorkerResultNormalizationEvidence",
    "build_worker_result_schema_failure",
    "make_scheduler_cancel_result",
    "make_scheduler_worker_error_result",
    "normalize_scheduler_worker_result",
)
