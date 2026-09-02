"""Process-queue monitor elastic scaling and dynamic-feed orchestration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.queue.feed_marker import mark_process_queue_feed_complete as _mark_process_queue_feed_complete
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.orchestration.process_queue_monitor_scaling_feed_steps import (
    advance_monitor_dynamic_feed_step,
    apply_monitor_elastic_step,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_bool,
    monitor_elastic_io_sample,
    monitor_float,
    monitor_int,
    monitor_queue_identities,
    monitor_recoverable_exceptions,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
    from pathlib import Path


@dataclass(frozen=True)
class MonitorScalingFeedRequest:
    worker_pool: ProcessQueueParentWorkerPool
    enabled_elastic_scheduler: bool
    process_count: int
    requested_process_count: int
    queue_dir: Path
    ordered_queue_items: tuple[object, ...]
    queue_feed_cursor: int
    file_pending_count: int
    file_active_count: int
    raw_live: int
    live_workers: int
    next_worker_spawn_id: int
    dynamic_queue_feed: bool
    queue_total_enqueued: int
    queue_enqueued_identities: frozenset[str]
    elastic_io_sample: object
    all_files_count: int
    queue_last_feed_log: float
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled_elastic_scheduler", monitor_bool(self.enabled_elastic_scheduler, default=False, reason="process_queue_monitor_elastic_scheduler_rejected"))
        object.__setattr__(self, "process_count", monitor_int(self.process_count, default=0, minimum=0, reason="process_queue_monitor_process_count_rejected"))
        object.__setattr__(self, "requested_process_count", monitor_int(self.requested_process_count, default=0, minimum=0, reason="process_queue_monitor_requested_count_rejected"))
        object.__setattr__(self, "ordered_queue_items", immutable_tuple(self.ordered_queue_items))
        object.__setattr__(self, "queue_feed_cursor", monitor_int(self.queue_feed_cursor, default=0, minimum=0, reason="process_queue_monitor_cursor_rejected"))
        object.__setattr__(self, "file_pending_count", monitor_int(self.file_pending_count, default=0, minimum=0, reason="process_queue_monitor_file_pending_rejected"))
        object.__setattr__(self, "file_active_count", monitor_int(self.file_active_count, default=0, minimum=0, reason="process_queue_monitor_file_active_rejected"))
        object.__setattr__(self, "raw_live", monitor_int(self.raw_live, default=0, minimum=0, reason="process_queue_monitor_raw_live_rejected"))
        object.__setattr__(self, "live_workers", monitor_int(self.live_workers, default=0, minimum=0, reason="process_queue_monitor_live_workers_rejected"))
        object.__setattr__(self, "next_worker_spawn_id", monitor_int(self.next_worker_spawn_id, default=0, minimum=0, reason="process_queue_monitor_next_worker_spawn_id_rejected"))
        object.__setattr__(self, "dynamic_queue_feed", monitor_bool(self.dynamic_queue_feed, default=False, reason="process_queue_monitor_dynamic_feed_rejected"))
        object.__setattr__(self, "queue_total_enqueued", monitor_int(self.queue_total_enqueued, default=0, minimum=0, reason="process_queue_monitor_total_enqueued_rejected"))
        object.__setattr__(self, "queue_enqueued_identities", monitor_queue_identities(self.queue_enqueued_identities))
        object.__setattr__(self, "elastic_io_sample", monitor_elastic_io_sample(self.elastic_io_sample))
        object.__setattr__(self, "all_files_count", monitor_int(self.all_files_count, default=0, minimum=0, reason="process_queue_monitor_all_files_count_rejected"))
        object.__setattr__(self, "queue_last_feed_log", monitor_float(self.queue_last_feed_log, default=0.0, minimum=0.0, reason="process_queue_monitor_last_feed_log_rejected"))
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))


@dataclass(frozen=True)
class MonitorScalingFeedResult:
    live_workers: int
    next_worker_spawn_id: int
    elastic_target_workers: int
    elastic_cpu_sample: object
    elastic_io_sample: object
    queue_feed_cursor: int
    queue_total_enqueued: int
    queue_enqueued_identities: frozenset[str]
    queue_last_feed_log: float
    counts: object
    worker_spawn_failures: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "live_workers", monitor_int(self.live_workers, default=0, minimum=0, reason="process_queue_monitor_live_workers_rejected"))
        object.__setattr__(self, "next_worker_spawn_id", monitor_int(self.next_worker_spawn_id, default=0, minimum=0, reason="process_queue_monitor_next_worker_spawn_id_rejected"))
        object.__setattr__(self, "elastic_target_workers", monitor_int(self.elastic_target_workers, default=0, minimum=0, reason="process_queue_monitor_elastic_target_rejected"))
        object.__setattr__(self, "elastic_io_sample", monitor_elastic_io_sample(self.elastic_io_sample))
        object.__setattr__(self, "queue_feed_cursor", monitor_int(self.queue_feed_cursor, default=0, minimum=0, reason="process_queue_monitor_cursor_rejected"))
        object.__setattr__(self, "queue_total_enqueued", monitor_int(self.queue_total_enqueued, default=0, minimum=0, reason="process_queue_monitor_total_enqueued_rejected"))
        object.__setattr__(self, "queue_enqueued_identities", monitor_queue_identities(self.queue_enqueued_identities))
        object.__setattr__(self, "queue_last_feed_log", monitor_float(self.queue_last_feed_log, default=0.0, minimum=0.0, reason="process_queue_monitor_last_feed_log_rejected"))
        object.__setattr__(self, "worker_spawn_failures", immutable_tuple(self.worker_spawn_failures))


def apply_monitor_scaling_and_feed(request: MonitorScalingFeedRequest) -> MonitorScalingFeedResult:
    elastic_output = apply_monitor_elastic_step(request)
    feed_output = advance_monitor_dynamic_feed_step(
        request=request,
        elastic_target_workers=elastic_output.elastic_target_workers,
        elastic_cpu_sample=elastic_output.elastic_cpu_sample,
        elastic_io_sample=elastic_output.elastic_io_sample,
        mark_feed_complete=_mark_process_queue_feed_complete,
    )
    return MonitorScalingFeedResult(
        live_workers=elastic_output.live_workers,
        next_worker_spawn_id=elastic_output.next_worker_spawn_id,
        elastic_target_workers=elastic_output.elastic_target_workers,
        elastic_cpu_sample=elastic_output.elastic_cpu_sample,
        elastic_io_sample=elastic_output.elastic_io_sample,
        queue_feed_cursor=feed_output.queue_feed_cursor,
        queue_total_enqueued=feed_output.queue_total_enqueued,
        queue_enqueued_identities=monitor_queue_identities(feed_output.queue_enqueued_identities),
        queue_last_feed_log=feed_output.queue_last_feed_log,
        counts=feed_output.counts,
        worker_spawn_failures=immutable_tuple(elastic_output.worker_spawn_failures),
    )
