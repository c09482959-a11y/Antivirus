"""Process-queue startup queue-admission orchestration."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_bool,
    monitor_int,
    monitor_queue_identities,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS as RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.execution.process_queue_setup import (
    ProcessQueueSetupDependencies,
    ProcessQueueSetupRequest,
    initialize_process_queue_work,
)
from Virus_Scan.scheduler.queue.publish import write_process_queue_jobs, write_process_queue_jobs_slice
from Virus_Scan.scheduler.queue.feed_policy import build_process_queue_feed_policy, initial_file_feed_buffer
from Virus_Scan.scheduler.queue.feed_marker import mark_process_queue_feed_complete as _mark_process_queue_feed_complete
from Virus_Scan.scheduler.runtime.queue_filesystem import process_weight_for_path as _process_weight_for_path
from Virus_Scan.scheduler.runtime.backpressure_policy import dynamic_process_queue_target
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class ProcessQueueStartupAdmissionRequest:
    queue_dir: Path
    all_files: tuple[str, ...]
    process_count: int
    requested_process_count: int
    dynamic_queue_feed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "process_count", monitor_int(self.process_count, default=0, minimum=0, reason="process_queue_startup_process_count_rejected"))
        object.__setattr__(self, "requested_process_count", monitor_int(self.requested_process_count, default=0, minimum=0, reason="process_queue_startup_requested_count_rejected"))
        object.__setattr__(self, "dynamic_queue_feed", monitor_bool(self.dynamic_queue_feed, default=False, reason="process_queue_startup_dynamic_feed_rejected"))


@dataclass(frozen=True)
class ProcessQueueStartupAdmissionResult:
    ordered_queue_items: tuple[object, ...]
    queue_feed_cursor: int
    queue_enqueued_identities: frozenset[str]
    queue_total_enqueued: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "ordered_queue_items", immutable_tuple(self.ordered_queue_items))
        object.__setattr__(self, "queue_feed_cursor", monitor_int(self.queue_feed_cursor, default=0, minimum=0, reason="process_queue_startup_cursor_rejected"))
        object.__setattr__(self, "queue_enqueued_identities", monitor_queue_identities(self.queue_enqueued_identities))
        object.__setattr__(self, "queue_total_enqueued", monitor_int(self.queue_total_enqueued, default=0, minimum=0, reason="process_queue_startup_total_enqueued_rejected"))


def prepare_process_queue_startup_admission(
    request: ProcessQueueStartupAdmissionRequest,
) -> ProcessQueueStartupAdmissionResult:
    setup_output = initialize_process_queue_work(
        request.queue_dir,
        ProcessQueueSetupRequest(
            all_files=tuple(request.all_files),
            process_count=request.process_count,
            requested_process_count=request.requested_process_count,
            dynamic_queue_feed=request.dynamic_queue_feed,
            env=scheduler_environment_snapshot(),
        ),
        ProcessQueueSetupDependencies(
            process_weight_for_path=_process_weight_for_path,
            dynamic_process_queue_target=dynamic_process_queue_target,
            build_feed_policy=build_process_queue_feed_policy,
            initial_file_feed_buffer=initial_file_feed_buffer,
            write_jobs=write_process_queue_jobs,
            write_jobs_slice=write_process_queue_jobs_slice,
            mark_feed_complete=_mark_process_queue_feed_complete,
            log_info=logging.info,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        ),
    )
    return ProcessQueueStartupAdmissionResult(
        ordered_queue_items=tuple(setup_output.ordered_queue_items),
        queue_feed_cursor=setup_output.queue_feed_cursor,
        queue_enqueued_identities=frozenset(setup_output.queue_enqueued_identities),
        queue_total_enqueued=setup_output.queue_total_enqueued,
    )
