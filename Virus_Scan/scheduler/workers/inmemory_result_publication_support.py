"""Support helpers for in-memory worker result publication."""
from __future__ import annotations

import os
import time
from collections.abc import Callable, MutableMapping

from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int
from Virus_Scan.scheduler.internal.worker_result_boundary import (
    scheduler_owned_mapping_snapshot,
    scheduler_path_text,
    scheduler_scan_integrity_snapshot,
)

_SCHEDULER_ZERO_INT = 0


def completed_worker_metadata(
    *,
    active: MutableMapping[object, object],
    future: object,
) -> tuple[object, object, int, str, str]:
    """Pop worker metadata and return normalized path evidence fields."""
    meta = active.pop(future, {})
    meta_snapshot = scheduler_owned_mapping_snapshot(meta)
    if meta_snapshot is not None:
        job_id = dict.get(meta_snapshot, "job_id")
        path = dict.get(meta_snapshot, "path")
        attempt, _attempt_reason = scheduler_int(
            dict.get(meta_snapshot, "attempt"),
            default=_SCHEDULER_ZERO_INT,
            minimum=0,
            reason="inmemory_worker_result_attempt_rejected",
        )
    else:
        job_id, path, attempt = (None, None, 0)
    safe_path, path_unavailable_reason = scheduler_path_text(path)
    return job_id, path, attempt, safe_path, path_unavailable_reason


def completed_worker_future_result(
    *,
    future: object,
    safe_path: str,
    path_unavailable_reason: str,
    worker_error_result: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple,
) -> tuple[object, object, bool]:
    """Read one future and construct fallback worker-error evidence if needed."""
    worker_error_result_failed = False
    try:
        f, res = future.result()
    except recoverable_exceptions as exc:
        f = safe_path
        try:
            res = worker_error_result(safe_path, exc)
        except recoverable_exceptions as error_result_exc:
            worker_error_result_failed = True
            res = {
                "file": safe_path,
                "tags": [],
                "error": scheduler_exception_text(exc),
                "queue_failure": True,
                "scheduler_failure_reason": "worker_error_result_construction_failed",
                "scan_integrity": {
                    "file_failed": True,
                    "had_degraded_stage": True,
                    "queue_failure": True,
                    "worker_error_result_construction_failed": True,
                    "worker_failure_error": scheduler_exception_text(exc)[:1000],
                    "worker_error_result_error": scheduler_exception_text(error_result_exc)[:1000],
                    "allow_learning": False,
                    **({"worker_result_path_unavailable_reason": path_unavailable_reason} if path_unavailable_reason else {}),
                },
            }
    return f, res, worker_error_result_failed


def worker_result_requires_schema_normalization(res: object) -> bool:
    """Return whether publication observed a non-materializable worker result schema."""
    res_snapshot = scheduler_owned_mapping_snapshot(res)
    integrity_candidate = dict.get(res_snapshot, "scan_integrity") if res_snapshot is not None else None
    integrity_snapshot = scheduler_owned_mapping_snapshot(integrity_candidate) if integrity_candidate is not None else None
    return res_snapshot is None or (integrity_candidate is not None and integrity_snapshot is None)


def publish_worker_result_record(
    *,
    result_q: object,
    job_id: object,
    f: object,
    res: object,
    attempt: int,
    recoverable_exceptions: tuple,
    record_suppressed: Callable[[str, BaseException], object],
) -> tuple[object, bool, bool]:
    """Publish the normalized result tuple and annotate publication-report failures."""
    queue_publish_failed = False
    queue_publish_report_failed = False
    try:
        result_q.put(("result", job_id, f, res, os.getpid(), time.time(), attempt))
    except recoverable_exceptions as exc:
        queue_publish_failed = True
        try:
            record_suppressed("inmemory_worker_result_publication_failed", exc)
        except recoverable_exceptions as record_exc:
            queue_publish_report_failed = True
            integrity = scheduler_scan_integrity_snapshot(
                dict.get(res, "scan_integrity") if type(res) is dict else None,
                unavailable_reason="non_materializable_worker_publication_integrity",
                original_type_field="worker_publication_integrity_original_type",
                unavailable_flag="worker_publication_integrity_unavailable",
                unavailable_reason_field="worker_publication_integrity_unavailable_reason",
            )
            integrity.update(
                {
                    "file_failed": True,
                    "had_degraded_stage": True,
                    "queue_failure": True,
                    "worker_result_publication_failed": True,
                    "worker_result_publication_report_failed": True,
                    "worker_result_publication_error": scheduler_exception_text(exc)[:1000],
                    "worker_result_publication_report_error": scheduler_exception_text(record_exc)[:1000],
                    "allow_learning": False,
                }
            )
            if type(res) is dict:
                res["scan_integrity"] = integrity
                res["queue_failure"] = True
                res["scheduler_failure_reason"] = "worker_result_publication_failed"
    return res, queue_publish_failed, queue_publish_report_failed


def completed_worker_counts(
    *,
    processed_jobs: int,
    max_jobs_per_worker: int,
) -> tuple[int, bool]:
    """Return the next processed count and stop flag with scheduler-owned bool/int parsing."""
    processed_count, _processed_reason = scheduler_int(
        processed_jobs,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_worker_processed_jobs_rejected",
    )
    max_jobs, _max_jobs_reason = scheduler_int(
        max_jobs_per_worker,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_worker_max_jobs_rejected",
    )
    next_processed = processed_count + 1
    stop_candidate = max_jobs > 0 and next_processed >= max_jobs
    should_stop, _stop_reason = scheduler_bool(
        stop_candidate,
        default=False,
        reason="inmemory_worker_stop_status_rejected",
    )
    return next_processed, should_stop


__all__ = (
    "completed_worker_counts",
    "completed_worker_future_result",
    "completed_worker_metadata",
    "publish_worker_result_record",
    "worker_result_requires_schema_normalization",
)
