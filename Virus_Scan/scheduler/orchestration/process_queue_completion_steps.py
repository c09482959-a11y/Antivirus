"""Bounded process-queue completion step helpers."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
import logging
from typing import Callable

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS as RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.workers.cleanup import wait_for_process_queue_worker_exit
from Virus_Scan.scheduler.queue.diagnostics import (
    queue_cleanup_diagnostic_tmp_files,
    repair_failed_queue_job_diagnostics,
)
from Virus_Scan.scheduler.queue.issue_reporting import (
    record_process_queue_suppressed,
    record_raw_queue_issue,
)
from Virus_Scan.scheduler.queue.results import (
    QueueDoneJobsMissingResultsRequest,
    load_queue_file_results,
    queue_done_jobs_missing_results,
)
from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name as _queue_is_job_json_name
from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file
from Virus_Scan.scheduler.queue.process_queue_result_merge import (
    ProcessQueueResultMergeDependencies,
    ProcessQueueResultMergeRequest,
    merge_process_queue_results,
)
from Virus_Scan.scheduler.workers.process_queue_worker_exit import (
    ProcessQueueWorkerExitDependencies,
    ProcessQueueWorkerExitRequest,
    reconcile_process_queue_worker_exits,
)
from Virus_Scan.scheduler.queue.raw_queue_failure_audit import collect_failed_queue_report, summarize_failed_queue_report
from Virus_Scan.scheduler.runtime.process_queue_cleanup import (
    ProcessQueueCleanupDependencies,
    ProcessQueueCleanupRequest,
    cleanup_process_queue_runtime_dir,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool


def _completion_done_jobs_missing_results(
    queue_dir: object,
    merged_results: dict[str, object],
) -> object:
    return queue_done_jobs_missing_results(
        QueueDoneJobsMissingResultsRequest(
            queue_dir=queue_dir,
            merged_results=merged_results,
        )
    )


def reconcile_completion_worker_exits(request: object) -> object:
    """Wait for process workers and return immutable exit reconciliation."""
    worker_exit_output = reconcile_process_queue_worker_exits(
        ProcessQueueWorkerExitRequest(
            procs=request.worker_pool.workers_tuple(),
            strict=request.strict,
            had_error=request.had_error,
        ),
        ProcessQueueWorkerExitDependencies(
            wait_for_worker_exit=wait_for_process_queue_worker_exit,
            record_issue=record_raw_queue_issue,
            log_error=log_error,
        ),
    )
    had_error, _worker_exit_reason = scheduler_bool(
        worker_exit_output.had_error,
        default=False,
        reason="process_queue_worker_exit_had_error_rejected",
    )
    return worker_exit_output, had_error


def merge_completion_queue_results(request: object, had_error: bool) -> object:
    """Merge process-queue worker outputs and final partial publication."""
    return merge_process_queue_results(
        ProcessQueueResultMergeRequest(
            queue_dir=request.queue_dir,
            outputs=request.worker_pool.outputs_tuple(),
            all_files=tuple(request.all_files),
            partial_output_path=request.partial_output_path,
            strict_had_error=had_error,
        ),
        ProcessQueueResultMergeDependencies(
            read_json_file=_queue_read_json_file,
            load_queue_file_results=load_queue_file_results,
            queue_job_dirs=_queue_job_dirs,
            is_job_json_name=_queue_is_job_json_name,
            done_jobs_missing_results=_completion_done_jobs_missing_results,
            repair_failed_queue_job_diagnostics=repair_failed_queue_job_diagnostics,
            cleanup_diagnostic_tmp_files=queue_cleanup_diagnostic_tmp_files,
            collect_failed_queue_report=collect_failed_queue_report,
            summarize_failed_queue_report=summarize_failed_queue_report,
            safe_queue_listdir=_safe_queue_listdir,
            record_issue=record_raw_queue_issue,
            log_error=log_error,
            log_info=logging.info,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        ),
    )


def materialize_completion_merged_results(merge_output: object) -> tuple[dict[str, object], bool]:
    """Return a safe string-keyed merged mapping and merged error state."""
    merged_output = materialize_scheduler_mapping(merge_output.merged)
    if type(merged_output) is not dict:
        merged = {
            "scheduler_queue_merge_unavailable": {
                "reason": "process_queue_completion_merge_rejected",
                "evidence": merged_output,
            }
        }
    else:
        merged = scheduler_str_key_mapping_from_items(dict.items(merged_output))
    had_error, _merge_error_reason = scheduler_bool(
        merge_output.had_error,
        default=False,
        reason="process_queue_merge_had_error_rejected",
    )
    return merged, had_error


def finalize_completion_runtime_cleanup(request: object) -> None:
    """Cleanup process-queue runtime resources with explicit evidence ownership."""
    cleanup_process_queue_runtime_dir(
        ProcessQueueCleanupRequest(runtime_dir=request.runtime_dir),
        ProcessQueueCleanupDependencies(
            report_suppressed=record_process_queue_suppressed,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        ),
    )


def run_process_queue_completion_steps(
    request: object,
    attach_worker_exit_evidence: Callable[[dict[str, object], tuple[object, ...]], None],
    attach_scheduler_evidence: Callable[[dict[str, object], tuple[object, ...]], None],
) -> tuple[dict[str, object], bool, tuple[object, ...]]:
    """Run bounded completion steps and return merged completion evidence."""
    worker_exit_output, had_error = reconcile_completion_worker_exits(request)
    merge_output = merge_completion_queue_results(request, had_error)
    merged, had_error = materialize_completion_merged_results(merge_output)
    worker_exit_evidence = tuple(worker_exit_output.exit_evidence)
    if worker_exit_evidence:
        attach_worker_exit_evidence(merged, worker_exit_evidence)
    if request.monitor_evidence:
        attach_scheduler_evidence(merged, request.monitor_evidence)
    finalize_completion_runtime_cleanup(request)
    return merged, had_error, worker_exit_evidence
