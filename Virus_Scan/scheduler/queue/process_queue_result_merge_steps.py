"""Failure-audit helpers for process-queue result merge."""
from __future__ import annotations

import os

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_exception_text,
    scheduler_filesystem_path,
    scheduler_value_snapshot,
)
from Virus_Scan.scheduler.queue.process_queue_result_merge_contracts import (
    ProcessQueueResultMergeDependencies,
    ProcessQueueResultMergeRequest,
)
from Virus_Scan.scheduler.queue.process_queue_result_merge_text import (
    merge_count_message,
    merge_failure_reason_message,
    merge_record_value,
    merge_text,
)
from Virus_Scan.scheduler.queue.process_queue_terminal_counts import terminal_queue_counts
from Virus_Scan.scheduler.runtime.queue_json import queue_write_json_replace as _scheduler_write_json_replace

_FAILURE_DIAGNOSTICS_WRITER_RETURNED_FALSE = "process queue failure diagnostics writer returned false"


def merge_failed_queue_diagnostics(
    request: ProcessQueueResultMergeRequest,
    deps: ProcessQueueResultMergeDependencies,
    merged: dict[str, object],
) -> bool:
    """Audit terminal queue state and publish failure diagnostics when needed."""
    pending, active, _done, failed = deps.queue_job_dirs(request.queue_dir)
    try:
        leftover_pending, leftover_active, failed_jobs = terminal_queue_counts(
            pending,
            active,
            failed,
            safe_listdir=deps.safe_queue_listdir,
            is_job_name=deps.is_job_json_name,
        )

        missing_done_results = deps.done_jobs_missing_results(request.queue_dir, merged)
        had_missing_results = len(missing_done_results) > 0
        if had_missing_results is True:
            deps.log_error(
                "process queue completion mismatch: done markers without durable merged results="
                + merge_text(len(missing_done_results), field_name="missing_done_results")
            )
            for missing in missing_done_results[:20]:
                missing_job_text = merge_text(
                    scheduler_value_snapshot(
                        merge_record_value(missing, "queue_job"),
                        field_name="queue_job",
                    ),
                    field_name="queue_job",
                )
                missing_file_text = merge_text(
                    scheduler_value_snapshot(
                        merge_record_value(missing, "file"),
                        field_name="queue_file",
                    ),
                    field_name="queue_file",
                )
                deps.log_error(
                    "process queue done-without-result: "
                    + "job="
                    + missing_job_text
                    + " file="
                    + missing_file_text
                )

        try:
            deps.repair_failed_queue_job_diagnostics(request.queue_dir)
        except deps.recoverable_exceptions as suppressed_exc:
            try:
                deps.record_issue("process_queue_failed_diagnostic_repair_suppressed", suppressed_exc, fatal=False)
            except deps.recoverable_exceptions as reporting_exc:
                _ = reporting_exc
        try:
            deps.repair_failed_queue_job_diagnostics(request.queue_dir)
            deps.cleanup_diagnostic_tmp_files(request.queue_dir, max_age_sec=60.0)
        except deps.recoverable_exceptions as suppressed_exc:
            try:
                deps.record_issue("process_queue_failed_diagnostic_cleanup_suppressed", suppressed_exc, fatal=False)
            except deps.recoverable_exceptions as reporting_exc:
                _ = reporting_exc

        failure_report = deps.collect_failed_queue_report(
            request.queue_dir,
            queue_job_dirs=deps.queue_job_dirs,
            safe_queue_listdir=deps.safe_queue_listdir,
            is_job_json_name=deps.is_job_json_name,
            read_json_file=deps.read_json_file,
            recoverable_exceptions=deps.recoverable_exceptions,
            log_error=deps.log_error,
        )

        had_failures = False
        if leftover_pending != 0 or leftover_active != 0 or failed_jobs != 0:
            had_failures = True
            deps.log_error(merge_count_message(leftover_pending, leftover_active, failed_jobs))
            if len(failure_report) > 0:
                for (job_type, stage, exc_type, err), count in deps.summarize_failed_queue_report(
                    failure_report,
                    limit=10,
                ):
                    deps.log_error(merge_failure_reason_message(count, job_type, stage, exc_type, err))
                report_path = os.path.abspath("umige_queue_failures.json")
                try:
                    partial_path, partial_reason = scheduler_filesystem_path(request.partial_output_path)
                    partial_text = ""
                    if partial_reason:
                        diagnostic_path = scheduler_evidence_path(
                            request.partial_output_path,
                            field_name="process_queue_partial_output_path",
                        )
                        deps.log_error("process queue failure report path rejected: " + diagnostic_path)
                    elif type(partial_path) is str:
                        partial_text = str.__str__(partial_path)
                    elif partial_path != "":
                        partial_text = os.fspath(partial_path)
                    report_path = partial_text + ".queue_failures.json" if partial_text else report_path
                    report_written = _scheduler_write_json_replace(
                        report_path,
                        {
                            "pending": leftover_pending,
                            "active": leftover_active,
                            "failed": failed_jobs,
                            "done_without_results": missing_done_results,
                            "failures": failure_report,
                        },
                        verify=True,
                        log_context="process_queue_failure_report",
                    )
                    if report_written is False:
                        raise OSError(_FAILURE_DIAGNOSTICS_WRITER_RETURNED_FALSE)
                    deps.log_info("process queue failure diagnostics written: " + report_path)
                except deps.recoverable_exceptions as exc:
                    deps.record_issue(
                        "process_queue_failure_diagnostics_write_failed",
                        exc,
                        fatal=True,
                        extra={"report_path": report_path},
                    )
                    deps.log_error("process queue failure diagnostics save failed: " + scheduler_exception_text(exc))
        return had_missing_results is True or had_failures is True
    except deps.recoverable_exceptions as exc:
        deps.record_issue(
            "process_queue_failed_job_audit_failed",
            exc,
            fatal=True,
            extra={"queue_dir": scheduler_evidence_path(request.queue_dir, field_name="process_queue_dir")},
        )
        deps.log_error("process queue failed-job audit failed: " + scheduler_exception_text(exc))
        return True


__all__ = ("merge_failed_queue_diagnostics",)
