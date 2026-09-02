"""Recovery/scaling-counts ownership for a process-queue monitor iteration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.evidence.process_queue_progress_counts import snapshot_process_queue_progress_counts
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_bool,
    monitor_feed_counts,
    monitor_float,
    monitor_int,
    monitor_queue_identities,
    monitor_recoverable_exceptions,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_recovery import MonitorRecoveryRequest, recover_monitor_queue
from Virus_Scan.scheduler.orchestration.process_queue_monitor_scaling_feed import MonitorScalingFeedRequest, apply_monitor_scaling_and_feed
from Virus_Scan.scheduler.queue.progress import queue_progress_counts_global

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class MonitorIterationStartRequest:
    worker_pool: object
    queue_dir: Path
    all_files: tuple[str, ...]
    ordered_queue_items: tuple[object, ...]
    raw_stage_progress_state: object
    progress_stall_sec: float
    per_file_timeout_sec: float
    last_integrity_repair_time: float
    elastic_scheduler: bool
    process_count: int
    requested_process_count: int
    queue_feed_cursor: int
    next_worker_spawn_id: int
    dynamic_queue_feed: bool
    queue_total_enqueued: int
    queue_enqueued_identities: frozenset[str]
    queue_last_feed_log: float
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "ordered_queue_items", immutable_tuple(self.ordered_queue_items))
        object.__setattr__(self, "progress_stall_sec", monitor_float(self.progress_stall_sec, default=0.0, minimum=0.0, reason="process_queue_monitor_progress_stall_rejected"))
        object.__setattr__(self, "per_file_timeout_sec", monitor_float(self.per_file_timeout_sec, default=0.0, minimum=0.0, reason="process_queue_monitor_per_file_timeout_rejected"))
        object.__setattr__(self, "last_integrity_repair_time", monitor_float(self.last_integrity_repair_time, default=0.0, minimum=0.0, reason="process_queue_monitor_integrity_repair_time_rejected"))
        object.__setattr__(self, "elastic_scheduler", monitor_bool(self.elastic_scheduler, default=False, reason="process_queue_monitor_elastic_scheduler_rejected"))
        object.__setattr__(self, "process_count", monitor_int(self.process_count, default=0, minimum=0, reason="process_queue_monitor_process_count_rejected"))
        object.__setattr__(self, "requested_process_count", monitor_int(self.requested_process_count, default=0, minimum=0, reason="process_queue_monitor_requested_count_rejected"))
        object.__setattr__(self, "queue_feed_cursor", monitor_int(self.queue_feed_cursor, default=0, minimum=0, reason="process_queue_monitor_cursor_rejected"))
        object.__setattr__(self, "next_worker_spawn_id", monitor_int(self.next_worker_spawn_id, default=0, minimum=0, reason="process_queue_monitor_next_worker_spawn_id_rejected"))
        object.__setattr__(self, "dynamic_queue_feed", monitor_bool(self.dynamic_queue_feed, default=False, reason="process_queue_monitor_dynamic_feed_rejected"))
        object.__setattr__(self, "queue_total_enqueued", monitor_int(self.queue_total_enqueued, default=0, minimum=0, reason="process_queue_monitor_total_enqueued_rejected"))
        object.__setattr__(self, "queue_enqueued_identities", monitor_queue_identities(self.queue_enqueued_identities))
        object.__setattr__(self, "queue_last_feed_log", monitor_float(self.queue_last_feed_log, default=0.0, minimum=0.0, reason="process_queue_monitor_last_feed_log_rejected"))
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))


@dataclass(frozen=True)
class MonitorIterationStartResult:
    live_workers: int
    raw_stage_progress_state: object
    last_integrity_repair_time: float
    counts: object
    file_done_count: int
    file_failed_count: int
    file_active_count: int
    file_pending_count: int
    raw_live: int
    queue_feed_cursor: int
    queue_total_enqueued: int
    queue_enqueued_identities: frozenset[str]
    queue_last_feed_log: float
    next_worker_spawn_id: int
    elastic_cpu_sample: object
    stale_recovery_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "live_workers", monitor_int(self.live_workers, default=0, minimum=0, reason="process_queue_monitor_live_workers_rejected"))
        object.__setattr__(self, "last_integrity_repair_time", monitor_float(self.last_integrity_repair_time, default=0.0, minimum=0.0, reason="process_queue_monitor_integrity_repair_time_rejected"))
        object.__setattr__(self, "file_done_count", monitor_int(self.file_done_count, default=0, minimum=0, reason="process_queue_monitor_file_done_rejected"))
        object.__setattr__(self, "file_failed_count", monitor_int(self.file_failed_count, default=0, minimum=0, reason="process_queue_monitor_file_failed_rejected"))
        object.__setattr__(self, "file_active_count", monitor_int(self.file_active_count, default=0, minimum=0, reason="process_queue_monitor_file_active_rejected"))
        object.__setattr__(self, "file_pending_count", monitor_int(self.file_pending_count, default=0, minimum=0, reason="process_queue_monitor_file_pending_rejected"))
        object.__setattr__(self, "raw_live", monitor_int(self.raw_live, default=0, minimum=0, reason="process_queue_monitor_raw_live_rejected"))
        object.__setattr__(self, "queue_feed_cursor", monitor_int(self.queue_feed_cursor, default=0, minimum=0, reason="process_queue_monitor_cursor_rejected"))
        object.__setattr__(self, "queue_total_enqueued", monitor_int(self.queue_total_enqueued, default=0, minimum=0, reason="process_queue_monitor_total_enqueued_rejected"))
        object.__setattr__(self, "queue_enqueued_identities", monitor_queue_identities(self.queue_enqueued_identities))
        object.__setattr__(self, "queue_last_feed_log", monitor_float(self.queue_last_feed_log, default=0.0, minimum=0.0, reason="process_queue_monitor_last_feed_log_rejected"))
        object.__setattr__(self, "next_worker_spawn_id", monitor_int(self.next_worker_spawn_id, default=0, minimum=0, reason="process_queue_monitor_next_worker_spawn_id_rejected"))
        object.__setattr__(self, "stale_recovery_evidence", immutable_tuple(self.stale_recovery_evidence))


def prepare_monitor_iteration(request: MonitorIterationStartRequest) -> MonitorIterationStartResult:
    """Run recovery, progress-count snapshot, scaling, and dynamic feed."""
    recovery_output = recover_monitor_queue(
        MonitorRecoveryRequest(
            worker_pool=request.worker_pool,
            queue_dir=request.queue_dir,
            all_files=request.all_files,
            raw_stage_progress_state=request.raw_stage_progress_state,
            progress_stall_sec=request.progress_stall_sec,
            per_file_timeout_sec=request.per_file_timeout_sec,
            last_integrity_repair_time=request.last_integrity_repair_time,
            recoverable_exceptions=request.recoverable_exceptions,
        )
    )
    raw_stage_progress_state = immutable_mapping(recovery_output.raw_stage_progress_state)
    progress_counts = snapshot_process_queue_progress_counts(request.queue_dir, progress_counts=queue_progress_counts_global)
    scaling_output = apply_monitor_scaling_and_feed(
        MonitorScalingFeedRequest(
            worker_pool=request.worker_pool,
            enabled_elastic_scheduler=request.elastic_scheduler,
            process_count=request.process_count,
            requested_process_count=request.requested_process_count,
            queue_dir=request.queue_dir,
            ordered_queue_items=request.ordered_queue_items,
            queue_feed_cursor=request.queue_feed_cursor,
            file_pending_count=progress_counts.file_pending_count,
            file_active_count=progress_counts.file_active_count,
            raw_live=progress_counts.raw_live,
            live_workers=recovery_output.live_workers,
            next_worker_spawn_id=request.next_worker_spawn_id,
            dynamic_queue_feed=request.dynamic_queue_feed,
            queue_total_enqueued=request.queue_total_enqueued,
            queue_enqueued_identities=request.queue_enqueued_identities,
            elastic_io_sample=None,
            all_files_count=len(request.all_files),
            queue_last_feed_log=request.queue_last_feed_log,
            recoverable_exceptions=request.recoverable_exceptions,
        )
    )
    file_done, file_failed, file_active, file_pending, raw_live, counts = _apply_feed_counts(
        scaling_output.counts,
        file_done_count=progress_counts.file_done_count,
        file_failed_count=progress_counts.file_failed_count,
        file_active_count=progress_counts.file_active_count,
        file_pending_count=progress_counts.file_pending_count,
        raw_live=progress_counts.raw_live,
        default_counts=progress_counts.counts,
    )
    return MonitorIterationStartResult(
        live_workers=scaling_output.live_workers,
        raw_stage_progress_state=raw_stage_progress_state,
        last_integrity_repair_time=recovery_output.last_integrity_repair_time,
        counts=counts,
        file_done_count=file_done,
        file_failed_count=file_failed,
        file_active_count=file_active,
        file_pending_count=file_pending,
        raw_live=raw_live,
        queue_feed_cursor=scaling_output.queue_feed_cursor,
        queue_total_enqueued=scaling_output.queue_total_enqueued,
        queue_enqueued_identities=monitor_queue_identities(scaling_output.queue_enqueued_identities),
        queue_last_feed_log=scaling_output.queue_last_feed_log,
        next_worker_spawn_id=scaling_output.next_worker_spawn_id,
        elastic_cpu_sample=scaling_output.elastic_cpu_sample,
        stale_recovery_evidence=immutable_tuple(recovery_output.stale_recovery_evidence),
    )


def _apply_feed_counts(feed_counts: object, *, file_done_count: int, file_failed_count: int, file_active_count: int, file_pending_count: int, raw_live: int, default_counts: object) -> tuple[int, int, int, int, int, object]:
    return monitor_feed_counts(
        feed_counts,
        file_done_count=file_done_count,
        file_failed_count=file_failed_count,
        file_active_count=file_active_count,
        file_pending_count=file_pending_count,
        raw_live=raw_live,
        default_counts=default_counts,
    )
