"""Process-queue monitor progress-publication orchestration."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_float,
    monitor_int,
    monitor_recoverable_exceptions,
)

from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.evidence.process_queue_monitor_progress import (
    ProcessQueueMonitorProgressDependencies,
    ProcessQueueMonitorProgressRequest,
    publish_process_queue_monitor_progress,
)
from Virus_Scan.scheduler.runtime.queue_json import read_json_file as _queue_read_json_file
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple

if TYPE_CHECKING:
    from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
    from pathlib import Path


@dataclass(frozen=True)
class MonitorProgressPublicationRequest:
    worker_pool: ProcessQueueParentWorkerPool
    partial_output_path: str | Path | None
    file_done_count: int
    file_failed_count: int
    file_active_count: int
    file_pending_count: int
    raw_live: int
    raw_done: int
    raw_failed: int
    live_workers: int
    total_files: int
    progress_every: int
    last_done_count: int
    last_progress_time: float
    progress_interval_sec: float
    last_monitor_heartbeat_time: float
    monitor_heartbeat_sec: float
    accounted_total: int
    elastic_cpu_sample: object
    now: float
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "file_done_count", monitor_int(self.file_done_count, default=0, minimum=0, reason="process_queue_progress_done_rejected"))
        object.__setattr__(self, "file_failed_count", monitor_int(self.file_failed_count, default=0, minimum=0, reason="process_queue_progress_failed_rejected"))
        object.__setattr__(self, "file_active_count", monitor_int(self.file_active_count, default=0, minimum=0, reason="process_queue_progress_active_rejected"))
        object.__setattr__(self, "file_pending_count", monitor_int(self.file_pending_count, default=0, minimum=0, reason="process_queue_progress_pending_rejected"))
        object.__setattr__(self, "raw_live", monitor_int(self.raw_live, default=0, minimum=0, reason="process_queue_progress_raw_live_rejected"))
        object.__setattr__(self, "raw_done", monitor_int(self.raw_done, default=0, minimum=0, reason="process_queue_progress_raw_done_rejected"))
        object.__setattr__(self, "raw_failed", monitor_int(self.raw_failed, default=0, minimum=0, reason="process_queue_progress_raw_failed_rejected"))
        object.__setattr__(self, "live_workers", monitor_int(self.live_workers, default=0, minimum=0, reason="process_queue_progress_live_workers_rejected"))
        object.__setattr__(self, "total_files", monitor_int(self.total_files, default=0, minimum=0, reason="process_queue_progress_total_files_rejected"))
        object.__setattr__(self, "progress_every", monitor_int(self.progress_every, default=1, minimum=1, reason="process_queue_progress_every_rejected"))
        object.__setattr__(self, "last_done_count", monitor_int(self.last_done_count, default=0, minimum=0, reason="process_queue_progress_last_done_rejected"))
        object.__setattr__(self, "last_progress_time", monitor_float(self.last_progress_time, default=0.0, minimum=0.0, reason="process_queue_progress_last_time_rejected"))
        object.__setattr__(self, "progress_interval_sec", monitor_float(self.progress_interval_sec, default=0.0, minimum=0.0, reason="process_queue_progress_interval_rejected"))
        object.__setattr__(self, "last_monitor_heartbeat_time", monitor_float(self.last_monitor_heartbeat_time, default=0.0, minimum=0.0, reason="process_queue_progress_last_heartbeat_rejected"))
        object.__setattr__(self, "monitor_heartbeat_sec", monitor_float(self.monitor_heartbeat_sec, default=0.0, minimum=0.0, reason="process_queue_progress_heartbeat_rejected"))
        object.__setattr__(self, "accounted_total", monitor_int(self.accounted_total, default=0, minimum=0, reason="process_queue_progress_accounted_total_rejected"))
        object.__setattr__(self, "now", monitor_float(self.now, default=0.0, minimum=0.0, reason="process_queue_progress_now_rejected"))
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))


@dataclass(frozen=True)
class MonitorProgressPublicationResult:
    last_done_count: int
    last_progress_time: float
    last_monitor_heartbeat_time: float
    last_monitor_heartbeat_total: int
    partial_output_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "partial_output_evidence", immutable_tuple(self.partial_output_evidence))


def publish_monitor_progress(request: MonitorProgressPublicationRequest) -> MonitorProgressPublicationResult:
    output = publish_process_queue_monitor_progress(
        ProcessQueueMonitorProgressRequest(
            outputs=request.worker_pool.outputs_tuple(),
            partial_output_path=request.partial_output_path,
            file_done_count=request.file_done_count,
            file_failed_count=request.file_failed_count,
            file_active_count=request.file_active_count,
            file_pending_count=request.file_pending_count,
            raw_live=request.raw_live,
            raw_done=request.raw_done,
            raw_failed=request.raw_failed,
            live_workers=request.live_workers,
            total_files=request.total_files,
            progress_every=request.progress_every,
            last_done_count=request.last_done_count,
            last_progress_time=request.last_progress_time,
            progress_interval_sec=request.progress_interval_sec,
            last_monitor_heartbeat_time=request.last_monitor_heartbeat_time,
            monitor_heartbeat_sec=request.monitor_heartbeat_sec,
            accounted_total=request.accounted_total,
            elastic_cpu_sample=request.elastic_cpu_sample,
            now=request.now,
        ),
        ProcessQueueMonitorProgressDependencies(
            log_info=logging.info,
            read_json_file=_queue_read_json_file,
            log_error=log_error,
            recoverable_exceptions=request.recoverable_exceptions,
        ),
    )
    return MonitorProgressPublicationResult(
        last_done_count=output.last_done_count,
        last_progress_time=output.last_progress_time,
        last_monitor_heartbeat_time=output.last_monitor_heartbeat_time,
        last_monitor_heartbeat_total=output.last_monitor_heartbeat_total,
        partial_output_evidence=output.partial_output_evidence,
    )
