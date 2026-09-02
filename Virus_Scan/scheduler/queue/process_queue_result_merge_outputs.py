"""Durable and partial-output helpers for process-queue result merge."""
from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.scheduler.api.contracts import QueueResultMergeError
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_exception_text,
    scheduler_filesystem_path,
)
from Virus_Scan.scheduler.queue.process_queue_result_merge_contracts import (
    ProcessQueueResultMergeDependencies,
    ProcessQueueResultMergeRequest,
)
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload

_DURABLE_QUEUE_RESULTS_NOT_EXACT_MAPPING = "durable process queue results were not an exact mapping"
_MERGED_PARTIAL_WRITER_RETURNED_FALSE = "process queue merged partial writer returned false"


def merge_durable_file_results(
    request: ProcessQueueResultMergeRequest,
    deps: ProcessQueueResultMergeDependencies,
    merged: dict[str, object],
) -> bool:
    """Merge durable per-file worker results into the parent result mapping."""
    try:
        durable_file_results = deps.load_queue_file_results(request.queue_dir)
        if type(durable_file_results) is dict:
            merged.update(durable_file_results)
            return False
        if durable_file_results is not None:
            raise QueueResultMergeError(_DURABLE_QUEUE_RESULTS_NOT_EXACT_MAPPING)
    except (QueueResultMergeError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        deps.record_issue(
            "process_queue_durable_result_merge_failed",
            exc,
            fatal=True,
            extra={"queue_dir": scheduler_evidence_path(request.queue_dir, field_name="process_queue_dir")},
        )
        deps.log_error("process queue durable result merge failed: " + scheduler_exception_text(exc))
        return True
    return False


def write_partial_queue_output(
    request: ProcessQueueResultMergeRequest,
    deps: ProcessQueueResultMergeDependencies,
    merged: dict[str, object],
) -> bool:
    """Write the merged partial output when the configured path is accepted."""
    partial_output_path, partial_output_reason = scheduler_filesystem_path(request.partial_output_path)
    if partial_output_reason:
        diagnostic_path = scheduler_evidence_path(
            request.partial_output_path,
            field_name="process_queue_partial_output_path",
        )
        deps.log_error("process queue partial output path rejected: " + diagnostic_path)
        return True
    if partial_output_path == "":
        return False
    partial_output_text = (
        str.__str__(partial_output_path)
        if type(partial_output_path) is str
        else Path.__str__(partial_output_path)
    )
    try:
        partial_written = write_worker_output_payload(partial_output_text + ".partial", merged)
        if partial_written is not True:
            raise OSError(_MERGED_PARTIAL_WRITER_RETURNED_FALSE)
    except deps.recoverable_exceptions as exc:
        deps.record_issue(
            "process_queue_partial_output_write_failed",
            exc,
            fatal=True,
            extra={"partial_output_path": partial_output_text + ".partial"},
        )
        deps.log_error("process queue merged partial JSON save failed: " + scheduler_exception_text(exc))
        return True
    return False


__all__ = ("merge_durable_file_results", "write_partial_queue_output")
