"""Failed-queue diagnostic repair helpers for the raw/process queue.

This module owns the repair policy for failed queue job metadata so the raw
queue monolith does not directly manage durable failure-diagnostic synthesis.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.queue.raw_queue_failed_diagnostics_evidence import (
    failed_queue_mapping_decision,
    failed_queue_name_decision,
    failed_queue_repair_count_decision,
)
from Virus_Scan.scheduler.queue.raw_queue_failed_diagnostics_steps import (
    queue_path,
    repair_one_failed_queue_job,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import (
    QueueListdirFailure,
    queue_listdir_names,
)
if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


def _queue_name_text(value: object) -> str:
    return failed_queue_name_decision(value).text






def _mapping(value: object) -> dict[str, object]:
    return dict(failed_queue_mapping_decision(value).mapping)


def repair_failed_queue_job_diagnostics(
    queue_dir: object,
    *,
    queue_job_dirs: Callable[[object], tuple[object, object, object, object]],
    safe_queue_listdir: Callable[[object], list[str] | QueueListdirFailure],
    is_job_json_name: Callable[[str], bool],
    read_json_file: Callable[..., object],
    default_failure_info: Callable[..., Mapping[str, object]],
    make_json_safe: Callable[[object], object],
    queue_safe_unlink: Callable[..., bool],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    log_error: Callable[[str], object],
) -> int:
    """Ensure every failed queue job has forensic failure metadata."""
    repaired = 0
    try:
        _pending, _active, _done, failed = queue_job_dirs(queue_dir)
        failed_path = queue_path(failed, reason="failed_queue_path_rejected")
        if not failed_path.exists():
            return failed_queue_repair_count_decision(
                repaired,
                reason="failed_queue_directory_missing",
            ).count
        failed_job_names: list[str] = []
        for raw_name in queue_listdir_names(safe_queue_listdir(failed_path), context=failed_path):
            safe_name = _queue_name_text(raw_name)
            if safe_name:
                failed_job_names.append(safe_name)
        for name in tuple(sorted(failed_job_names)):
            if not is_job_json_name(name):
                continue
            if repair_one_failed_queue_job(
                path=failed_path / name,
                name=name,
                read_json_file=read_json_file,
                default_failure_info=default_failure_info,
                make_json_safe=make_json_safe,
                queue_safe_unlink=queue_safe_unlink,
                record_scheduler_suppressed=record_scheduler_suppressed,
            ):
                repaired += 1
        if repaired:
            logging.info("process queue repaired missing failed-job diagnostics count=%s", repaired)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        log_error("process queue failed-job diagnostic repair failed: " + scheduler_exception_text(exc))
    return failed_queue_repair_count_decision(repaired, reason="failed_queue_repair_complete").count


__all__ = ("repair_failed_queue_job_diagnostics",)
