"""Queue-owned diagnostics cleanup and repair."""
from __future__ import annotations



from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.evidence.raw_queue_failure import default_failure_info as queue_default_failure_info
from Virus_Scan.scheduler.queue.raw_queue_cleanup import cleanup_diagnostic_tmp_files
from Virus_Scan.scheduler.queue.raw_queue_failed_diagnostics import repair_failed_queue_job_diagnostics as _repair_failed_queue_job_diagnostics_impl
from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name as _queue_is_job_json_name
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_failure_diagnostics_dir as _queue_failure_diagnostics_dir, queue_job_dirs as _queue_job_dirs, queue_safe_unlink as _queue_safe_unlink, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file, make_json_safe
from Virus_Scan.scheduler.queue.issue_reporting import record_raw_queue_issue


def queue_cleanup_diagnostic_tmp_files(queue_dir: object, max_age_sec: float = 600.0) -> object:
    return cleanup_diagnostic_tmp_files(
        queue_dir,
        failure_diagnostics_dir=_queue_failure_diagnostics_dir,
        safe_listdir=_safe_queue_listdir,
        safe_unlink=_queue_safe_unlink,
        report=record_raw_queue_issue,
        max_age_sec=max_age_sec,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )


def repair_failed_queue_job_diagnostics(queue_dir: object) -> object:
    return _repair_failed_queue_job_diagnostics_impl(
        queue_dir,
        queue_job_dirs=_queue_job_dirs,
        safe_queue_listdir=_safe_queue_listdir,
        is_job_json_name=_queue_is_job_json_name,
        read_json_file=_queue_read_json_file,
        default_failure_info=queue_default_failure_info,
        make_json_safe=make_json_safe,
        queue_safe_unlink=_queue_safe_unlink,
        record_scheduler_suppressed=record_scheduler_suppressed,
        log_error=lambda msg: record_raw_queue_issue("queue_diagnostic_repair_log", RuntimeError(str(msg))),
    )


__all__ = ("queue_cleanup_diagnostic_tmp_files", "repair_failed_queue_job_diagnostics")
