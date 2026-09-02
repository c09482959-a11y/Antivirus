"""Bounded helper steps for process queue runner execution."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_minimum_int
from Virus_Scan.scheduler.orchestration.process_queue_completion import ProcessQueueCompletionRequest
from Virus_Scan.scheduler.orchestration.process_queue_monitor_contracts import ProcessQueueMonitorLoopRequest
from Virus_Scan.scheduler.orchestration.process_queue_monitor_loop import monitor_process_queue
from Virus_Scan.scheduler.orchestration.process_queue_startup import ProcessQueueStartupRequest, start_process_queue
from Virus_Scan.scheduler.execution.process_queue_runner_completion import complete_process_queue_results
from Virus_Scan.scheduler.execution.process_queue_runner_decisions import (
    process_queue_empty_result_decision,
    scheduler_file_rejection_decision,
)


@dataclass(frozen=True, slots=True)
class ProcessQueueRunnerInputs:
    """Validated process queue runner inputs."""

    scheduler_files: tuple[object, ...]
    process_count: int
    strict: bool


def has_rejected_scheduler_file(files: tuple[object, ...]) -> bool:
    """Return whether any scheduler file entry is rejected."""
    decision = scheduler_file_rejection_decision(files)
    return decision.as_bool()


def normalize_process_queue_runner_inputs(
    *,
    all_files: tuple[str, ...] | list[str],
    process_count: int,
    strict: bool,
) -> ProcessQueueRunnerInputs | dict[object, object]:
    """Normalize public runner inputs or return the canonical empty result."""
    scheduler_files = freeze_live_scheduler_paths(all_files)
    if has_rejected_scheduler_file(scheduler_files):
        raise ValueError("process_queue_runner_all_files_rejected")
    if len(scheduler_files) == 0:
        empty_decision = process_queue_empty_result_decision(scheduler_files)
        return empty_decision.as_mapping()
    process_count_value, process_reason = scheduler_minimum_int(
        process_count,
        minimum=1,
        reason="process_queue_runner_process_count_rejected",
    )
    strict_value, strict_reason = scheduler_bool(
        strict,
        default=False,
        reason="process_queue_runner_strict_rejected",
    )
    reasons = tuple(reason for reason in (process_reason, strict_reason) if reason)
    if reasons:
        raise ValueError(",".join(reasons))
    return ProcessQueueRunnerInputs(
        scheduler_files=scheduler_files,
        process_count=process_count_value,
        strict=strict_value,
    )


def start_process_queue_runner(
    *,
    root: object,
    inputs: ProcessQueueRunnerInputs,
    progress_every: int,
    throttle_sec: float,
    partial_output_every: int,
    slow_file_warn_sec: float,
    per_file_timeout_sec: float,
    scan_session_snapshot: ScanSessionSnapshot,
) -> object:
    """Start the process queue and return its startup state."""
    return start_process_queue(
        ProcessQueueStartupRequest(
            root=root,
            all_files=inputs.scheduler_files,
            process_count=inputs.process_count,
            strict=inputs.strict,
            progress_every=progress_every,
            throttle_sec=throttle_sec,
            partial_output_every=partial_output_every,
            slow_file_warn_sec=slow_file_warn_sec,
            per_file_timeout_sec=per_file_timeout_sec,
            scan_session_snapshot=scan_session_snapshot,
        )
    )


def monitor_started_process_queue(
    *,
    startup_state: object,
    scheduler_files: tuple[object, ...],
    progress_every: int,
    partial_output_path: object,
    per_file_timeout_sec: float,
) -> object:
    """Run the process queue monitor loop for a started queue."""
    return monitor_process_queue(
        ProcessQueueMonitorLoopRequest(
            queue_dir=startup_state.queue_dir,
            outputs_dir=startup_state.outputs_dir,
            worker_pool=startup_state.worker_pool,
            all_files=scheduler_files,
            ordered_queue_items=tuple(startup_state.ordered_queue_items),
            queue_feed_cursor=startup_state.queue_feed_cursor,
            queue_enqueued_identities=frozenset(startup_state.queue_enqueued_identities),
            queue_total_enqueued=startup_state.queue_total_enqueued,
            queue_last_feed_log=startup_state.queue_last_feed_log,
            raw_stage_progress_state=immutable_mapping(startup_state.raw_stage_progress_state),
            process_count=startup_state.process_count,
            requested_process_count=startup_state.requested_process_count,
            dynamic_queue_feed=startup_state.dynamic_queue_feed,
            elastic_scheduler=startup_state.elastic_scheduler,
            next_worker_spawn_id=startup_state.next_worker_spawn_id,
            progress_every=progress_every,
            partial_output_path=partial_output_path,
            per_file_timeout_sec=per_file_timeout_sec,
        )
    )


def complete_started_process_queue(
    *,
    startup_state: object,
    scheduler_files: tuple[object, ...],
    partial_output_path: object,
    strict_value: bool,
    monitor_result: object,
) -> dict[object, object]:
    """Complete process queue execution and publish final results."""
    return complete_process_queue_results(
        queue_dir=startup_state.queue_dir,
        runtime_dir=startup_state.runtime_dir,
        worker_pool=startup_state.worker_pool,
        scheduler_files=scheduler_files,
        partial_output_path=partial_output_path,
        strict_value=strict_value,
        monitor_result=monitor_result,
        completion_request_factory=ProcessQueueCompletionRequest,
    )


__all__ = (
    "ProcessQueueRunnerInputs",
    "complete_started_process_queue",
    "has_rejected_scheduler_file",
    "monitor_started_process_queue",
    "normalize_process_queue_runner_inputs",
    "start_process_queue_runner",
)
