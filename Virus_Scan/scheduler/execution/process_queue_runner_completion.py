"""Completion projection for bounded process-queue runner."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.orchestration.process_queue_completion import complete_process_queue


def complete_process_queue_results(
    *,
    queue_dir: object,
    runtime_dir: object,
    worker_pool: object,
    scheduler_files: tuple[object, ...],
    partial_output_path: object,
    strict_value: bool,
    monitor_result: object,
    completion_request_factory: object,
) -> dict[object, object]:
    had_error, monitor_error_reason = scheduler_bool(
        monitor_result.had_error,
        default=False,
        reason="process_queue_runner_monitor_had_error_rejected",
    )
    if monitor_error_reason:
        raise ValueError(monitor_error_reason)
    completion = complete_process_queue(
        completion_request_factory(
            queue_dir=queue_dir,
            runtime_dir=runtime_dir,
            worker_pool=worker_pool,
            all_files=scheduler_files,
            partial_output_path=partial_output_path,
            strict=strict_value,
            had_error=had_error,
            monitor_evidence=tuple(monitor_result.timeout_retry_evidence),
        )
    )
    merged = materialize_scheduler_mapping(completion.merged)
    if type(merged) is not dict:
        raise ValueError("process_queue_runner_merged_results_rejected")
    return {path: merged[path] for path in scheduler_files if path in merged}


__all__ = ("complete_process_queue_results",)
