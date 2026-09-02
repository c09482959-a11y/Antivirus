"""Scheduler-mode dispatch ownership for the canonical scheduler runner."""
from __future__ import annotations

import logging
import time
from Virus_Scan.core.cache import bulk_scan_maintenance
from Virus_Scan.core.logging import log_bulk_progress
from Virus_Scan.contracts.env_config import bool_env
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.execution.process_queue_runner import run_process_queue
from Virus_Scan.scheduler.orchestration.inmemory_parent_loop import _run_longlived_process_queue
from Virus_Scan.scheduler.orchestration.process_queue_child_mode import ProcessQueueChildModeRequest, run_process_queue_child_mode
from Virus_Scan.scheduler.orchestration.scheduler_serial_mode import SchedulerSerialModeDependencies, SchedulerSerialModeRequest, run_scheduler_serial_mode
from Virus_Scan.scheduler.orchestration.scheduler_mode_recovery import run_process_setup_recovery_serial_mode
from Virus_Scan.scheduler.runtime.backpressure_policy import cpu_count_safe
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.runtime.execution_memory_capacity import execution_memory_snapshot
from Virus_Scan.scheduler.runtime.process_worker_capacity import default_filesystem_queue_workers, default_process_scheduler_workers
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text
from Virus_Scan.scheduler.orchestration.scheduler_mode_contracts import (
    SchedulerModeDispatchDependencies,
    SchedulerModeDispatchRequest,
)
def run_scheduler_mode(request: SchedulerModeDispatchRequest, deps: SchedulerModeDispatchDependencies) -> dict[object, object]:
    """Run the selected scheduler mode through one bounded dispatcher."""
    workers, workers_reason = scheduler_int(
        request.workers,
        default=0,
        minimum=0,
        reason="scheduler_worker_count_rejected",
    )
    if workers_reason:
        raise ValueError(workers_reason)
    scheduler, scheduler_reason = scheduler_text(
        request.scheduler,
        replacement_text="process",
        unsupported_reason="scheduler_mode_rejected",
    )
    if scheduler_reason:
        raise ValueError(scheduler_reason)
    scheduler = scheduler.lower()
    if scheduler == 'queue-child':
        child_mode_result = run_process_queue_child_mode(
            ProcessQueueChildModeRequest(
                work_queue_dir=request.work_queue_dir,
                worker_output_path=request.worker_output_path,
                total_files=request.total_files,
                scan_started_at=request.scan_started_at,
                progress_every=request.progress_every,
                throttle_sec=request.throttle_sec,
                worker=deps.worker,
                scan_session_snapshot=request.scan_session_snapshot,
            )
        )
        return materialize_scheduler_mapping(child_mode_result.results)
    if workers == 1 or scheduler in {'serial', 'single'}:
        logging.info('bulk scan scheduler=serial workers=1')
        serial_result = run_scheduler_serial_mode(
            SchedulerSerialModeRequest(
                files=request.all_files,
                total_files=request.total_files,
                started_at=request.scan_started_at,
                progress_every=request.progress_every,
                throttle_sec=request.throttle_sec,
                results=deps.results,
            ),
            SchedulerSerialModeDependencies(
                worker=deps.worker, prepare_result=deps.result_retainer,
                write_derived_cache=deps.derived_cache_writer,
                write_partial=deps.write_partial, bulk_scan_maintenance=bulk_scan_maintenance,
                log_bulk_progress=log_bulk_progress, sleep=time.sleep,
            ),
        )
        if type(deps.results) is dict:
            return deps.results
        return materialize_scheduler_mapping(serial_result.results)
    if scheduler == 'process' and not bool_env('UMIGE_PROCESS_SHARD', False):
        if workers <= 0:
            workers = default_process_scheduler_workers(
                env=scheduler_environment_snapshot(),
                cpu_count=cpu_count_safe(),
                recoverable_exceptions=(),
                memory_snapshot=execution_memory_snapshot(),
            )
        try:
            return _run_longlived_process_queue(
                request.root,
                list(request.all_files),
                workers,
                strict=request.strict,
                yara_enabled=request.yara_enabled,
                progress_every=request.progress_every,
                throttle_sec=request.throttle_sec,
                partial_output_path=request.partial_output_path,
                partial_output_every=request.partial_output_every,
                slow_file_warn_sec=request.slow_file_warn_sec,
                per_file_timeout_sec=request.per_file_timeout_sec,
                result_retainer=deps.result_retainer,
                derived_cache_writer=deps.derived_cache_writer,
                scan_session_snapshot=request.scan_session_snapshot,
            )
        except PermissionError:
            return run_process_setup_recovery_serial_mode(
                request,
                deps.worker,
                deps.write_partial,
                deps.result_retainer,
                deps.derived_cache_writer,
            )
    if scheduler in {'process-fs', 'filesystem-queue'} and not bool_env('UMIGE_PROCESS_SHARD', False):
        if workers <= 0:
            workers = default_filesystem_queue_workers(
                cpu_count=cpu_count_safe(),
                env=scheduler_environment_snapshot(),
                memory_snapshot=execution_memory_snapshot(),
            )
        raw_results = run_process_queue(
            request.root, list(request.all_files), workers,
            scan_session_snapshot=request.scan_session_snapshot,
            strict=request.strict, progress_every=request.progress_every,
            throttle_sec=request.throttle_sec, partial_output_path=request.partial_output_path,
            partial_output_every=request.partial_output_every,
            slow_file_warn_sec=request.slow_file_warn_sec,
            per_file_timeout_sec=request.per_file_timeout_sec,
        )
        retained_results: dict[object, object] = {}
        for path, result in materialize_scheduler_mapping(raw_results).items():
            retained_results[path] = deps.result_retainer(path, result)
            deps.derived_cache_writer(result)
        return retained_results
    raise ValueError("Unsupported scheduler: " + str.__str__(scheduler) + ". Supported: process, process-fs, serial, queue-child")

__all__ = ("run_scheduler_mode",)
