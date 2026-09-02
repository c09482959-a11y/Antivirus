"""Process-queue monitor idle/missing-result finalization orchestration."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_bool,
    monitor_float,
    monitor_int,
    monitor_recoverable_exceptions,
)
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result
from Virus_Scan.scheduler.queue.issue_reporting import (
    record_process_queue_suppressed,
    record_raw_queue_issue,
)
from Virus_Scan.scheduler.queue.results import load_queue_file_results
from Virus_Scan.scheduler.workers.cleanup import terminate_process_queue_worker
from Virus_Scan.scheduler.queue.process_queue_idle_finalization import (
    ProcessQueueIdleFinalizationDependencies,
    ProcessQueueIdleFinalizationRequest,
    reconcile_process_queue_idle_finalization,
)
from Virus_Scan.scheduler.queue.terminal_accounting import (
    IdleQueueFinalizationRequest,
    idle_queue_finalization_decision,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
    from pathlib import Path


@dataclass(frozen=True)
class MonitorIdleFinalizationRequest:
    worker_pool: ProcessQueueParentWorkerPool
    queue_dir: Path
    outputs_dir: Path
    all_files: tuple[str, ...]
    ordered_queue_items: tuple[object, ...]
    queue_feed_cursor: int
    file_pending_count: int
    file_active_count: int
    raw_live: int
    file_done_count: int
    file_failed_count: int
    live_workers: int
    idle_done_since: float | None
    now: float
    idle_grace_sec: float
    idle_notice_sec: float
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "ordered_queue_items", immutable_tuple(self.ordered_queue_items))
        object.__setattr__(self, "queue_feed_cursor", monitor_int(self.queue_feed_cursor, default=0, minimum=0, reason="process_queue_idle_cursor_rejected"))
        object.__setattr__(self, "file_pending_count", monitor_int(self.file_pending_count, default=0, minimum=0, reason="process_queue_idle_pending_rejected"))
        object.__setattr__(self, "file_active_count", monitor_int(self.file_active_count, default=0, minimum=0, reason="process_queue_idle_active_rejected"))
        object.__setattr__(self, "raw_live", monitor_int(self.raw_live, default=0, minimum=0, reason="process_queue_idle_raw_live_rejected"))
        object.__setattr__(self, "file_done_count", monitor_int(self.file_done_count, default=0, minimum=0, reason="process_queue_idle_done_rejected"))
        object.__setattr__(self, "file_failed_count", monitor_int(self.file_failed_count, default=0, minimum=0, reason="process_queue_idle_failed_rejected"))
        object.__setattr__(self, "live_workers", monitor_int(self.live_workers, default=0, minimum=0, reason="process_queue_idle_live_workers_rejected"))
        object.__setattr__(self, "now", monitor_float(self.now, default=0.0, minimum=0.0, reason="process_queue_idle_now_rejected"))
        object.__setattr__(self, "idle_grace_sec", monitor_float(self.idle_grace_sec, default=0.0, minimum=0.0, reason="process_queue_idle_grace_rejected"))
        object.__setattr__(self, "idle_notice_sec", monitor_float(self.idle_notice_sec, default=0.0, minimum=0.0, reason="process_queue_idle_notice_rejected"))
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))


@dataclass(frozen=True)
class MonitorIdleFinalizationResult:
    idle_done_since: float | None
    idle_notice_sec: float
    had_error: bool
    should_stop: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "idle_notice_sec", monitor_float(self.idle_notice_sec, default=0.0, minimum=0.0, reason="process_queue_idle_result_notice_rejected"))
        object.__setattr__(self, "had_error", monitor_bool(self.had_error, default=False, reason="process_queue_idle_result_error_rejected"))
        object.__setattr__(self, "should_stop", monitor_bool(self.should_stop, default=False, reason="process_queue_idle_result_stop_rejected"))


def reconcile_monitor_idle_finalization(request: MonitorIdleFinalizationRequest) -> MonitorIdleFinalizationResult:
    try:
        feed_complete_now = bool(request.queue_feed_cursor >= len(request.ordered_queue_items))
    except request.recoverable_exceptions:
        feed_complete_now = False
    no_live_queue_work = (request.file_pending_count + request.file_active_count + request.raw_live) == 0
    idle_output = reconcile_process_queue_idle_finalization(
        ProcessQueueIdleFinalizationRequest(
            feed_complete=feed_complete_now,
            no_live_queue_work=no_live_queue_work,
            accounted_files=request.file_done_count + request.file_failed_count,
            total_files=len(request.all_files),
            idle_done_since=request.idle_done_since,
            now=request.now,
            idle_grace_sec=request.idle_grace_sec,
            idle_notice_sec=request.idle_notice_sec,
            all_files=tuple(request.all_files),
            queue_dir=request.queue_dir,
            outputs_dir=request.outputs_dir,
            procs=request.worker_pool.workers_tuple(),
            live_workers=request.live_workers,
        ),
        ProcessQueueIdleFinalizationDependencies(
            load_queue_file_results=load_queue_file_results,
            worker_error_result=make_scheduler_worker_error_result,
            terminate_worker=lambda proc, *, action, worker_idx: terminate_process_queue_worker(
                proc,
                action=action,
                worker_idx=worker_idx,
                report_failure=record_process_queue_suppressed,
            ),
            report=record_raw_queue_issue,
            log_error=logging.error,
            log_info=logging.info,
            sleep=time.sleep,
            idle_queue_finalization_request_factory=IdleQueueFinalizationRequest,
            idle_queue_finalization_request_owner=idle_queue_finalization_decision,
        ),
    )
    return MonitorIdleFinalizationResult(
        idle_done_since=idle_output.idle_done_since,
        idle_notice_sec=idle_output.idle_notice_sec,
        had_error=bool(idle_output.had_error),
        should_stop=bool(idle_output.should_stop),
    )
