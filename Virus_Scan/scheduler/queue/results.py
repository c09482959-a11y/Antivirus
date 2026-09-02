"""Queue-owned durable result readback contracts."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name as _queue_is_job_json_name
from Virus_Scan.scheduler.queue.issue_reporting import record_raw_queue_issue
from Virus_Scan.scheduler.queue.result_merge import done_jobs_missing_results as _done_jobs_missing_results_impl, load_queue_file_results as _load_queue_file_results_impl
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_file_results_dir as _queue_file_results_dir, queue_job_dirs as _queue_job_dirs, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file


def load_queue_file_results(
    queue_dir: object,
    *,
    file_results_dir: object=_queue_file_results_dir,
    safe_listdir: object=_safe_queue_listdir,
    read_json: object=_queue_read_json_file,
    report: object=record_raw_queue_issue,
) -> object:
    return _load_queue_file_results_impl(
        queue_dir,
        file_results_dir=file_results_dir,
        safe_listdir=safe_listdir,
        read_json=read_json,
        report=report,
    )


@dataclass(frozen=True, slots=True)
class QueueDoneJobsMissingResultsRequest:
    queue_dir: object
    merged_results: dict[str, object]
    job_dirs: object = _queue_job_dirs
    safe_listdir: object = _safe_queue_listdir
    is_job_json_name: object = _queue_is_job_json_name
    read_json: object = _queue_read_json_file
    report: object = record_raw_queue_issue


def queue_done_jobs_missing_results(
    request: QueueDoneJobsMissingResultsRequest,
) -> object:
    return _done_jobs_missing_results_impl(
        request.queue_dir,
        request.merged_results,
        job_dirs=request.job_dirs,
        safe_listdir=request.safe_listdir,
        is_job_json_name=request.is_job_json_name,
        read_json=request.read_json,
        report=request.report,
    )



__all__ = (
    'QueueDoneJobsMissingResultsRequest',
    'load_queue_file_results',
    'queue_done_jobs_missing_results',
)
