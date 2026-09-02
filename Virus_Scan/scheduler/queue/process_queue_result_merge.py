"""Process-queue terminal result merge and failure audit owner."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.queue.process_queue_result_merge_contracts import (
    ProcessQueueResultMergeDependencies,
    ProcessQueueResultMergeOutput,
    ProcessQueueResultMergeRequest,
)
from Virus_Scan.scheduler.queue.process_queue_result_merge_outputs import (
    merge_durable_file_results,
    write_partial_queue_output,
)
from Virus_Scan.scheduler.queue.process_queue_result_merge_steps import merge_failed_queue_diagnostics
from Virus_Scan.scheduler.queue.process_queue_result_merge_text import merge_bool
from Virus_Scan.scheduler.queue.process_queue_worker_output_merge import merge_process_queue_worker_outputs


def merge_process_queue_results(
    request: ProcessQueueResultMergeRequest,
    deps: ProcessQueueResultMergeDependencies,
) -> ProcessQueueResultMergeOutput:
    """Merge process-queue terminal results under queue ownership."""
    had_error = merge_bool(request.strict_had_error)
    merged, worker_output_failed = merge_process_queue_worker_outputs(
        request.outputs,
        deps=deps,
    )
    had_error = had_error is True or worker_output_failed is True
    had_error = merge_durable_file_results(request, deps, merged) is True or had_error is True
    had_error = merge_failed_queue_diagnostics(request, deps, merged) is True or had_error is True
    had_error = write_partial_queue_output(request, deps, merged) is True or had_error is True
    return ProcessQueueResultMergeOutput(merged=immutable_mapping(dict(merged)), had_error=had_error)


__all__ = ("ProcessQueueResultMergeOutput", "merge_process_queue_results")
