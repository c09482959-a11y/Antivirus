"""No-hook support for raw queue monitor file listing."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.internal.path_text import scheduler_posix_path_text as queue_dir_text
from Virus_Scan.scheduler.internal.raw_queue_monitor_no_hook import exact_reason_text
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import QueueListdirFailure, queue_listdir_failure, queue_listdir_names

QUEUE_JOB_KIND_FILE = "file"
QUEUE_JOB_KIND_RAW = "raw"
QUEUE_JOB_KIND_SKIP = "skip"


def safe_queue_names(
    directory: object,
    *,
    safe_queue_listdir: Callable[[object], list[str] | QueueListdirFailure],
    report: Callable[..., object],
    failure_stage: str,
    failure_extra: dict[str, object] | None = None,
    recoverable_exceptions: tuple[type[BaseException], ...] = (OSError, RuntimeError, TypeError, ValueError),
) -> tuple[object, ...]:
    """Call the queue-owned listdir dependency and project names without caller hooks."""
    try:
        return tuple(queue_listdir_names(safe_queue_listdir(directory), context=directory))
    except recoverable_exceptions as exc:
        if type(exc) is QueueListdirFailure:
            failure = exc
        else:
            failure = queue_listdir_failure(
                directory,
                reason="queue_listdir_dependency_failed",
                error=exc,
            )
        extra: dict[str, object] = {}
        if failure_extra is not None:
            extra.update(failure_extra)
        extra["queue_listdir_failure"] = failure.as_dict()
        report(
            failure_stage,
            exc,
            fatal=False,
            extra=extra,
        )
        return ()


def raw_queue_job_kind(
    directory: object,
    name: str,
    *,
    read_json_file: Callable[..., object],
    report: Callable[..., object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> str:
    job_name, name_reason = no_hook_text(
        name,
        missing_reason="missing_queue_job_name",
        unsupported_reason="unsafe_queue_job_name_rejected",
    )
    if name_reason:
        report("queue_progress_job_name_rejected", None, fatal=False)
        return QUEUE_JOB_KIND_SKIP
    if "raw_" in job_name or "umige_raw" in job_name:
        return QUEUE_JOB_KIND_RAW
    try:
        payload = read_json_file(Path(directory) / job_name, default=None)
        if type(payload) is not dict:
            return QUEUE_JOB_KIND_FILE
        job_type = exact_reason_text(dict.get(payload, "job_type"), default="")
        if job_type == "raw_stage":
            return QUEUE_JOB_KIND_RAW
        return QUEUE_JOB_KIND_FILE
    except recoverable_exceptions as exc:
        report("queue_progress_raw_payload_read_failed", exc, fatal=False)
        return QUEUE_JOB_KIND_FILE


__all__ = (
    "QUEUE_JOB_KIND_FILE",
    "QUEUE_JOB_KIND_RAW",
    "QUEUE_JOB_KIND_SKIP",
    "queue_dir_text",
    "raw_queue_job_kind",
    "safe_queue_names",
)
