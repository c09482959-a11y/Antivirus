"""Bounded step helpers for process-queue monitor scaling and feed."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable

from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed import (
    ProcessQueueDynamicFeedDependencies,
    ProcessQueueDynamicFeedRequest,
    advance_process_queue_dynamic_feed,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_elastic_io_pressure,
    monitor_elastic_io_sample,
    monitor_int,
)
from Virus_Scan.scheduler.queue.feed_policy import build_process_queue_feed_policy, decide_process_queue_feed
from Virus_Scan.scheduler.queue.issue_reporting import (
    record_process_queue_suppressed,
    record_raw_queue_issue,
)
from Virus_Scan.scheduler.queue.progress import queue_progress_counts_global
from Virus_Scan.scheduler.queue.publish import write_process_queue_jobs_slice
from Virus_Scan.scheduler.runtime.backpressure_policy import io_adjusted_elastic_target
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.runtime.process_queue_runtime_policy import process_queue_respawn_delay
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling import (
    ProcessQueueElasticScaleDependencies,
    ProcessQueueElasticScaleRequest,
    apply_process_queue_elastic_scaling,
)
from Virus_Scan.scheduler.workers.retire_tokens import request_queue_worker_retire


@dataclass(frozen=True, slots=True)
class MonitorElasticStepResult:
    live_workers: int
    next_worker_spawn_id: int
    elastic_target_workers: int
    elastic_cpu_sample: object
    elastic_io_sample: object
    worker_spawn_failures: tuple[object, ...]


def apply_monitor_elastic_step(request: object) -> MonitorElasticStepResult:
    """Run elastic scaling and return only monitor-owned step evidence."""
    elastic_output = apply_process_queue_elastic_scaling(
        ProcessQueueElasticScaleRequest(
            enabled=request.enabled_elastic_scheduler,
            process_count=request.process_count,
            requested_process_count=request.requested_process_count,
            queue_dir=request.queue_dir,
            ordered_queue_count=len(request.ordered_queue_items),
            queue_feed_cursor=request.queue_feed_cursor,
            file_pending_count=request.file_pending_count,
            file_active_count=request.file_active_count,
            raw_live=request.raw_live,
            live_workers=request.live_workers,
            next_worker_spawn_id=request.next_worker_spawn_id,
        ),
        ProcessQueueElasticScaleDependencies(
            io_adjusted_target=io_adjusted_elastic_target,
            spawn_worker=request.worker_pool.spawn,
            request_worker_retire=request_queue_worker_retire,
            respawn_delay=process_queue_respawn_delay,
            env=scheduler_environment_snapshot(),
            recoverable_exceptions=request.recoverable_exceptions,
            sleep=time.sleep,
            log_info=logging.info,
            log_error=log_error,
            report_suppressed=record_process_queue_suppressed,
        ),
    )
    return MonitorElasticStepResult(
        live_workers=elastic_output.live_workers,
        next_worker_spawn_id=elastic_output.next_worker_spawn_id,
        elastic_target_workers=elastic_output.elastic_target_workers,
        elastic_cpu_sample=elastic_output.elastic_cpu_sample,
        elastic_io_sample=elastic_output.elastic_io_sample,
        worker_spawn_failures=elastic_output.worker_spawn_failures,
    )


def advance_monitor_dynamic_feed_step(
    *,
    request: object,
    elastic_target_workers: int,
    elastic_cpu_sample: object,
    elastic_io_sample: object,
    mark_feed_complete: Callable[..., object],
) -> object:
    """Run dynamic feed using the bounded monitor step context."""
    return advance_process_queue_dynamic_feed(
        ProcessQueueDynamicFeedRequest(
            enabled=request.dynamic_queue_feed and request.queue_feed_cursor < len(request.ordered_queue_items),
            queue_dir=request.queue_dir,
            ordered_queue_items=tuple(request.ordered_queue_items),
            queue_feed_cursor=request.queue_feed_cursor,
            queue_total_enqueued=request.queue_total_enqueued,
            queue_enqueued_identities=tuple(request.queue_enqueued_identities),
            target_workers=monitor_int(elastic_target_workers, default=0, minimum=0, reason="process_queue_monitor_elastic_target_rejected"),
            file_active_count=request.file_active_count,
            file_pending_count=request.file_pending_count,
            io_pressure=monitor_elastic_io_pressure(elastic_io_sample),
            cpu_sample=elastic_cpu_sample,
            elastic_io_sample=monitor_elastic_io_sample(elastic_io_sample),
            all_files_count=request.all_files_count,
            raw_live=request.raw_live,
            current_time=time.time(),
            queue_last_feed_log=request.queue_last_feed_log,
            env=scheduler_environment_snapshot(),
        ),
        ProcessQueueDynamicFeedDependencies(
            build_feed_policy=build_process_queue_feed_policy,
            decide_feed=decide_process_queue_feed,
            write_jobs_slice=write_process_queue_jobs_slice,
            mark_feed_complete=mark_feed_complete,
            progress_counts=queue_progress_counts_global,
            record_issue=record_raw_queue_issue,
            log_error=log_error,
            log_info=logging.info,
            recoverable_exceptions=request.recoverable_exceptions,
        ),
    )


__all__ = ("MonitorElasticStepResult", "advance_monitor_dynamic_feed_step", "apply_monitor_elastic_step")
