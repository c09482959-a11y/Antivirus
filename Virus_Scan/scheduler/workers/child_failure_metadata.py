"""Worker-owned failure metadata builders for process-queue child jobs."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
import os
import time

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.worker_result_boundary import scheduler_path_text, scheduler_scan_integrity_snapshot
from Virus_Scan.scheduler.workers.child_failure_metadata_types import (
    ChildErrorResultBuilder,
    ChildExceptionInfoBuilder,
    ChildFailureInfo,
    ChildFailureJob,
    ChildFailureReporter,
    ChildFailureResult,
    ChildResultSnapshotDecision,
    child_failure_int,
    child_attempt_decision,
    merge_child_attempt_decision,
)


def _safe_stage_text(stage: object) -> str:
    text, reason = no_hook_text(
        stage,
        missing_reason="missing_scheduler_failure_stage",
        unsupported_reason="unsafe_scheduler_failure_stage_rejected",
    )
    if reason:
        return "unknown"
    stripped = str.strip(text)
    return stripped or "unknown"


def _safe_exception_message(exc: object, *, replacement_text: str = "unknown") -> str:
    """Return exception text without invoking caller-owned exception hooks."""
    if exc is None:
        return replacement_text
    type_name = no_hook_type_name(exc)
    if not isinstance(exc, BaseException):
        return type_name
    return scheduler_exception_text(exc, max_length=2000, missing_text=type_name)


def build_safe_exception_info(
    exc: BaseException | None,
    *,
    stage: str = "unknown",
    worker_pid: int | None = None,
    attempt: object = None,
) -> ChildFailureInfo:
    """Build scheduler-owned durable exception metadata for worker failures."""
    safe_stage = _safe_stage_text(stage)
    safe_error = _safe_exception_message(exc)
    attempt_value = child_failure_int(attempt, default=0)
    info: ChildFailureInfo = {
        "stage": safe_stage,
        "exception_type": no_hook_type_name(exc) if exc is not None else "unknown",
        "error": safe_error[:2000],
        "traceback_tail": "",
        "traceback_unavailable_reason": "scheduler_exception_traceback_not_materialized_without_hooks",
        "worker_pid": child_failure_int(worker_pid, default=os.getpid()),
        "attempt": attempt_value,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if attempt is None:
        info["attempt_unavailable_reason"] = "child_failure_builder_attempt_missing"
    return info


def safe_exception_info(
    exc: BaseException,
    *,
    stage: str,
    job: ChildFailureJob = None,
    exception_info_builder: ChildExceptionInfoBuilder,
    report: ChildFailureReporter,
    recoverable_exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> ChildFailureInfo:
    """Build durable exception metadata, failing closed to explicit metadata."""
    safe_stage = _safe_stage_text(stage)
    attempt_decision = child_attempt_decision(job)
    if exception_info_builder is not build_safe_exception_info:
        return merge_child_attempt_decision({
            **build_safe_exception_info(
                exc,
                stage=safe_stage,
                worker_pid=os.getpid(),
                attempt=attempt_decision.value,
            ),
            "exception_info_builder_unavailable_reason": "caller_owned_exception_info_builder_rejected",
        }, attempt_decision)
    try:
        return merge_child_attempt_decision(
            exception_info_builder(
                exc,
                stage=safe_stage,
                worker_pid=os.getpid(),
                attempt=attempt_decision.value,
            ),
            attempt_decision,
        )
    except recoverable_exceptions as meta_exc:  # bounded by caller/report contract; never silent
        report(safe_stage + ".safe_exception_info_failed", meta_exc)
        return merge_child_attempt_decision(
            {
                "stage": safe_stage,
                "exception_type": no_hook_type_name(exc),
                "error": _safe_exception_message(exc)[:1000],
                "metadata_error": _safe_exception_message(meta_exc)[:500],
                "worker_pid": int(os.getpid()),
                "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            attempt_decision,
        )


def _owned_result_snapshot(value: object) -> ChildResultSnapshotDecision:
    items = no_hook_mapping_items(value)
    if items is None:
        return ChildResultSnapshotDecision(
            {"tags": []},
            False,
            "non_materializable_worker_error_result",
        )
    return ChildResultSnapshotDecision(
        scheduler_str_key_mapping_from_items(items),
        True,
        "worker_error_result_materialized",
    )


def worker_error_result(
    file_path: object,
    exc: BaseException,
    *,
    stage: str,
    job: ChildFailureJob = None,
    make_error_result: ChildErrorResultBuilder,
    exception_info_builder: ChildExceptionInfoBuilder,
    report: ChildFailureReporter,
    recoverable_exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> tuple[ChildFailureResult, ChildFailureInfo]:
    """Return a durable degraded worker result with forensic failure metadata."""
    safe_path, path_reason = scheduler_path_text(file_path)
    safe_error = _safe_exception_message(exc)
    failure_info = safe_exception_info(
        exc,
        stage=stage,
        job=job,
        exception_info_builder=exception_info_builder,
        report=report,
        recoverable_exceptions=recoverable_exceptions,
    )
    if path_reason:
        failure_info["file_path_unavailable_reason"] = path_reason
    res = make_error_result(safe_path, RuntimeError(safe_error))
    snapshot_decision = _owned_result_snapshot(res)
    snapshot = snapshot_decision.snapshot
    if not snapshot_decision.available:
        snapshot = {"file": safe_path, "tags": [], "error": safe_error}
        failure_info["worker_error_result_unavailable_reason"] = snapshot_decision.reason
    integrity = scheduler_scan_integrity_snapshot(
        dict.get(snapshot, "scan_integrity"),
        unavailable_reason="non_materializable_worker_failure_integrity",
        original_type_field="worker_failure_integrity_original_type",
        unavailable_flag="worker_failure_integrity_unavailable",
        unavailable_reason_field="worker_failure_integrity_unavailable_reason",
    )
    integrity.update(
        {
            "file_failed": True,
            "had_degraded_stage": True,
            "queue_failure": True,
            "failure_info": failure_info,
            "allow_learning": False,
        }
    )
    if path_reason:
        integrity["file_path_unavailable_reason"] = path_reason
    snapshot["scan_integrity"] = integrity
    snapshot["queue_failure"] = True
    snapshot["failure_info"] = failure_info
    return snapshot, failure_info


__all__ = ("build_safe_exception_info", "safe_exception_info", "worker_error_result")
