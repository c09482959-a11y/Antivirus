"""Process-queue startup worker publication orchestration."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import monitor_bool, monitor_int

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS as RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.queue.issue_reporting import record_process_queue_suppressed
from Virus_Scan.scheduler.runtime.backpressure_policy import io_adjusted_elastic_target
from Virus_Scan.scheduler.runtime.process_queue_runtime_policy import (
    elastic_process_queue_enabled,
    elastic_process_queue_min_workers,
    process_queue_launch_delay,
)
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.workers.initial_spawn import (
    ProcessQueueInitialSpawnDependencies,
    ProcessQueueInitialSpawnRequest,
    publish_initial_process_queue_workers,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
    from pathlib import Path


@dataclass(frozen=True)
class ProcessQueueStartupWorkerRequest:
    queue_dir: Path
    worker_pool: ProcessQueueParentWorkerPool
    process_count: int
    requested_process_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "process_count", monitor_int(self.process_count, default=0, minimum=0, reason="process_queue_startup_worker_process_count_rejected"))
        object.__setattr__(self, "requested_process_count", monitor_int(self.requested_process_count, default=0, minimum=0, reason="process_queue_startup_worker_requested_count_rejected"))


@dataclass(frozen=True)
class ProcessQueueStartupWorkerResult:
    elastic_scheduler: bool
    elastic_min_workers: int
    next_worker_spawn_id: int
    worker_spawn_failures: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "elastic_scheduler", monitor_bool(self.elastic_scheduler, default=False, reason="process_queue_startup_worker_elastic_rejected"))
        object.__setattr__(self, "elastic_min_workers", monitor_int(self.elastic_min_workers, default=0, minimum=0, reason="process_queue_startup_worker_min_rejected"))
        object.__setattr__(self, "next_worker_spawn_id", monitor_int(self.next_worker_spawn_id, default=0, minimum=0, reason="process_queue_startup_worker_spawn_id_rejected"))
        object.__setattr__(self, "worker_spawn_failures", immutable_tuple(self.worker_spawn_failures))


def publish_process_queue_startup_workers(request: ProcessQueueStartupWorkerRequest) -> ProcessQueueStartupWorkerResult:
    env_snapshot = scheduler_environment_snapshot()
    elastic_scheduler = elastic_process_queue_enabled(env_snapshot, RAW_QUEUE_RECOVERABLE_EXCEPTIONS)
    elastic_min_workers = elastic_process_queue_min_workers(
        env=env_snapshot,
        requested_process_count=request.requested_process_count,
        process_count=request.process_count,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )
    output = publish_initial_process_queue_workers(
        ProcessQueueInitialSpawnRequest(
            elastic_scheduler=monitor_bool(elastic_scheduler, default=False, reason="process_queue_startup_worker_elastic_rejected"),
            elastic_min_workers=monitor_int(elastic_min_workers, default=0, minimum=0, reason="process_queue_startup_worker_min_rejected"),
            process_count=monitor_int(request.process_count, default=0, minimum=0, reason="process_queue_startup_worker_process_count_rejected"),
            requested_process_count=monitor_int(request.requested_process_count, default=0, minimum=0, reason="process_queue_startup_worker_requested_count_rejected"),
            queue_dir=request.queue_dir,
            next_worker_spawn_id=0,
        ),
        ProcessQueueInitialSpawnDependencies(
            io_adjusted_elastic_target=io_adjusted_elastic_target,
            spawn_worker=request.worker_pool.spawn,
            launch_delay=lambda: process_queue_launch_delay(env_snapshot, RAW_QUEUE_RECOVERABLE_EXCEPTIONS),
            sleep=time.sleep,
            log_info=logging.info,
            report_suppressed=record_process_queue_suppressed,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        ),
    )
    return ProcessQueueStartupWorkerResult(
        elastic_scheduler=monitor_bool(elastic_scheduler, default=False, reason="process_queue_startup_worker_elastic_rejected"),
        elastic_min_workers=monitor_int(elastic_min_workers, default=0, minimum=0, reason="process_queue_startup_worker_min_rejected"),
        next_worker_spawn_id=output.next_worker_spawn_id,
        worker_spawn_failures=tuple(output.worker_spawn_failures),
    )
