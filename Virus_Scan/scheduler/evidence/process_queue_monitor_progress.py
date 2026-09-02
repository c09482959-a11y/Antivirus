"""Process-queue monitor progress evidence owner.

The execution loop supplies immutable queue-count snapshots; this module owns the
progress/heartbeat logging decision and optional partial-output evidence
publication for the parent-side process-queue monitor.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.evidence.process_queue_monitor_progress_support import (
    monitor_progress_float,
    monitor_progress_int,
)
from Virus_Scan.scheduler.evidence.process_queue_monitor_progress_steps import (
    heartbeat_log_message,
    progress_log_message,
    publish_monitor_partial_output,
    should_log_heartbeat,
    should_log_progress,
)


@dataclass(frozen=True)
class ProcessQueueMonitorProgressRequest:
    outputs: tuple[object, ...]
    partial_output_path: object
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
    elastic_cpu_sample: float | None
    now: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs", immutable_tuple(self.outputs))
        object.__setattr__(self, "file_done_count", monitor_progress_int(self.file_done_count, "scheduler_monitor_file_done_count_rejected"))
        object.__setattr__(self, "file_failed_count", monitor_progress_int(self.file_failed_count, "scheduler_monitor_file_failed_count_rejected"))
        object.__setattr__(self, "file_active_count", monitor_progress_int(self.file_active_count, "scheduler_monitor_file_active_count_rejected"))
        object.__setattr__(self, "file_pending_count", monitor_progress_int(self.file_pending_count, "scheduler_monitor_file_pending_count_rejected"))
        object.__setattr__(self, "raw_live", monitor_progress_int(self.raw_live, "scheduler_monitor_raw_live_rejected"))
        object.__setattr__(self, "raw_done", monitor_progress_int(self.raw_done, "scheduler_monitor_raw_done_rejected"))
        object.__setattr__(self, "raw_failed", monitor_progress_int(self.raw_failed, "scheduler_monitor_raw_failed_rejected"))
        object.__setattr__(self, "live_workers", monitor_progress_int(self.live_workers, "scheduler_monitor_live_workers_rejected"))
        object.__setattr__(self, "total_files", monitor_progress_int(self.total_files, "scheduler_monitor_total_files_rejected"))
        object.__setattr__(self, "progress_every", monitor_progress_int(self.progress_every, "scheduler_monitor_progress_every_rejected"))
        object.__setattr__(self, "last_done_count", monitor_progress_int(self.last_done_count, "scheduler_monitor_last_done_count_rejected"))
        object.__setattr__(self, "accounted_total", monitor_progress_int(self.accounted_total, "scheduler_monitor_accounted_total_rejected"))
        object.__setattr__(self, "last_progress_time", monitor_progress_float(self.last_progress_time, "scheduler_monitor_last_progress_time_rejected"))
        object.__setattr__(self, "progress_interval_sec", monitor_progress_float(self.progress_interval_sec, "schedulermonitor_progress_interval_sec_rejected"))
        object.__setattr__(self, "last_monitor_heartbeat_time", monitor_progress_float(self.last_monitor_heartbeat_time, "scheduler_monitor_last_monitor_heartbeat_time_rejected"))
        object.__setattr__(self, "monitor_heartbeat_sec", monitor_progress_float(self.monitor_heartbeat_sec, "scheduler_monitor_monitor_heartbeat_sec_rejected"))
        object.__setattr__(self, "now", monitor_progress_float(self.now, "scheduler_monitor_now_rejected"))
        if self.elastic_cpu_sample is not None:
            object.__setattr__(self, "elastic_cpu_sample", monitor_progress_float(self.elastic_cpu_sample, "scheduler_monitor_cpu_sample_rejected", maximum=100.0))


@dataclass(frozen=True)
class ProcessQueueMonitorProgressDependencies:
    log_info: Callable[[str], object]
    read_json_file: Callable[..., object]
    log_error: Callable[[str], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True)
class ProcessQueueMonitorProgressOutput:
    last_done_count: int
    last_progress_time: float
    last_monitor_heartbeat_time: float
    last_monitor_heartbeat_total: int
    partial_output_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "partial_output_evidence", immutable_tuple(self.partial_output_evidence))


def publish_process_queue_monitor_progress(
    request: ProcessQueueMonitorProgressRequest,
    dependencies: ProcessQueueMonitorProgressDependencies,
) -> ProcessQueueMonitorProgressOutput:
    """Publish progress/heartbeat evidence from immutable monitor counts."""
    if should_log_progress(request):
        dependencies.log_info(progress_log_message(request))
        return ProcessQueueMonitorProgressOutput(
            last_done_count=request.file_done_count,
            last_progress_time=request.now,
            last_monitor_heartbeat_time=request.now,
            last_monitor_heartbeat_total=request.accounted_total,
            partial_output_evidence=publish_monitor_partial_output(request, dependencies),
        )
    if should_log_heartbeat(request):
        dependencies.log_info(heartbeat_log_message(request))
        return ProcessQueueMonitorProgressOutput(
            last_done_count=request.last_done_count,
            last_progress_time=request.last_progress_time,
            last_monitor_heartbeat_time=request.now,
            last_monitor_heartbeat_total=request.accounted_total,
        )
    return ProcessQueueMonitorProgressOutput(
        last_done_count=request.last_done_count,
        last_progress_time=request.last_progress_time,
        last_monitor_heartbeat_time=request.last_monitor_heartbeat_time,
        last_monitor_heartbeat_total=request.accounted_total,
    )


__all__ = ("ProcessQueueMonitorProgressDependencies", "ProcessQueueMonitorProgressOutput", "ProcessQueueMonitorProgressRequest", "publish_process_queue_monitor_progress")
