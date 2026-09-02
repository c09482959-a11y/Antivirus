"""Canonical process-queue execution owner.

This module owns the parent-side process queue execution loop.  The remaining
canonical queue ownership modules supply lower-level raw-job helpers while callers use this
execution owner directly, keeping process-queue orchestration bounded to the
execution owner.
"""
from __future__ import annotations

from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot

from Virus_Scan.exception_contracts import (
    RECOVERABLE_RUNTIME_ERRORS as RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
)

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_minimum_int as _scheduler_minimum_int_public_guard,
)
from Virus_Scan.scheduler.orchestration.process_queue_completion import (
    ProcessQueueCompletionRequest as _ProcessQueueCompletionRequest_contract,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_contracts import (
    ProcessQueueMonitorLoopRequest as _ProcessQueueMonitorLoopRequest_contract,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup import (
    ProcessQueueStartupRequest as _ProcessQueueStartupRequest_contract,
)

_PROCESS_QUEUE_RUNNER_REQUEST_CONTRACTS = (
    _ProcessQueueStartupRequest_contract,
    _ProcessQueueMonitorLoopRequest_contract,
    _ProcessQueueCompletionRequest_contract,
)

_PROCESS_QUEUE_RUNNER_INT_NORMALIZER = _scheduler_minimum_int_public_guard
_PROCESS_QUEUE_RUNNER_EXCEPTION_DOMAIN = RAW_QUEUE_RECOVERABLE_EXCEPTIONS

from Virus_Scan.scheduler.execution.process_queue_runner_steps import (
    ProcessQueueRunnerInputs,
    complete_started_process_queue,
    has_rejected_scheduler_file as _has_rejected_scheduler_file,
    monitor_started_process_queue,
    normalize_process_queue_runner_inputs,
    start_process_queue_runner,
)


def run_process_queue(
    root: object,
    all_files: tuple[str, ...] | list[str],
    process_count: int,
    *,
    scan_session_snapshot: ScanSessionSnapshot,
    strict: bool = False,
    progress_every: int = 10,
    throttle_sec: float = 0.0,
    partial_output_path: object = None,
    partial_output_every: int = 10,
    slow_file_warn_sec: float = 2.0,
    per_file_timeout_sec: float = 20,
) -> dict[object, object]:
    """Run a real multi-process work-stealing queue."""
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        raise TypeError("process_queue_scan_session_snapshot_required")
    inputs = normalize_process_queue_runner_inputs(
        all_files=all_files,
        process_count=process_count,
        strict=strict,
    )
    if not isinstance(inputs, ProcessQueueRunnerInputs):
        return inputs
    startup_state = start_process_queue_runner(
        root=root,
        inputs=inputs,
        progress_every=progress_every,
        throttle_sec=throttle_sec,
        partial_output_every=partial_output_every,
        slow_file_warn_sec=slow_file_warn_sec,
        per_file_timeout_sec=per_file_timeout_sec,
        scan_session_snapshot=scan_session_snapshot,
    )
    try:
        monitor_result = monitor_started_process_queue(
            startup_state=startup_state,
            scheduler_files=inputs.scheduler_files,
            progress_every=progress_every,
            partial_output_path=partial_output_path,
            per_file_timeout_sec=per_file_timeout_sec,
        )
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        exc.add_note("process_queue_runner_monitor_failed")
        raise
    return complete_started_process_queue(
        startup_state=startup_state,
        scheduler_files=inputs.scheduler_files,
        partial_output_path=partial_output_path,
        strict_value=inputs.strict,
        monitor_result=monitor_result,
    )


__all__ = ("_has_rejected_scheduler_file", "run_process_queue")
