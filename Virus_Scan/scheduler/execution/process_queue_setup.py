"""Process-queue execution setup owner.

This module owns initial work ordering and first queue publication for the
parent-side process queue. Runtime path creation and subsequent reconciliation
remain owned by their respective scheduler domains.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_minimum_int
from Virus_Scan.scheduler.execution.process_queue_setup_steps import (
    build_ordered_process_queue_items,
    publish_dynamic_process_queue_jobs,
    publish_static_process_queue_jobs,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import monitor_queue_identities


_PROCESS_QUEUE_SETUP_DELEGATED_HELPERS = ("process_queue_setup_log_message",)


@dataclass(frozen=True)
class ProcessQueueSetupRequest:
    all_files: tuple[object, ...]
    process_count: int
    requested_process_count: int
    dynamic_queue_feed: bool
    env: object

    def __post_init__(self) -> None:
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        process_count, _process_reason = scheduler_minimum_int(
            self.process_count,
            minimum=0,
            reason="process_queue_setup_process_count_rejected",
        )
        requested_process_count, _requested_reason = scheduler_minimum_int(
            self.requested_process_count,
            minimum=0,
            reason="process_queue_setup_requested_count_rejected",
        )
        dynamic_queue_feed, _dynamic_reason = scheduler_bool(
            self.dynamic_queue_feed,
            default=False,
            reason="process_queue_setup_dynamic_feed_rejected",
        )
        object.__setattr__(self, "process_count", process_count)
        object.__setattr__(self, "requested_process_count", requested_process_count)
        object.__setattr__(self, "dynamic_queue_feed", dynamic_queue_feed)


@dataclass(frozen=True)
class ProcessQueueSetupDependencies:
    process_weight_for_path: Callable[[object], object]
    dynamic_process_queue_target: Callable[[int, int], tuple[int, object]]
    build_feed_policy: Callable[..., object]
    initial_file_feed_buffer: Callable[[int, int, object], int]
    write_jobs: Callable[[object, object], None]
    write_jobs_slice: Callable[..., tuple[int, int, int]]
    mark_feed_complete: Callable[[object], bool]
    log_info: Callable[[str], None]
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True)
class ProcessQueueSetupOutput:
    ordered_queue_items: tuple[tuple[int, int, object], ...]
    queue_feed_cursor: int
    queue_enqueued_identities: frozenset[object]
    queue_total_enqueued: int

    def __post_init__(self) -> None:
        queue_feed_cursor, _cursor_reason = scheduler_minimum_int(
            self.queue_feed_cursor,
            minimum=0,
            reason="process_queue_setup_cursor_rejected",
        )
        queue_total_enqueued, _total_reason = scheduler_minimum_int(
            self.queue_total_enqueued,
            minimum=0,
            reason="process_queue_setup_total_enqueued_rejected",
        )
        object.__setattr__(self, "ordered_queue_items", immutable_tuple(self.ordered_queue_items))
        object.__setattr__(self, "queue_feed_cursor", queue_feed_cursor)
        object.__setattr__(self, "queue_enqueued_identities", monitor_queue_identities(self.queue_enqueued_identities))
        object.__setattr__(self, "queue_total_enqueued", queue_total_enqueued)


def initialize_process_queue_work(
    queue_dir: object,
    request: ProcessQueueSetupRequest,
    deps: ProcessQueueSetupDependencies,
) -> ProcessQueueSetupOutput:
    """Publish initial process-queue work and return immutable setup state."""
    ordered_queue_items = build_ordered_process_queue_items(
        request.all_files,
        deps.process_weight_for_path,
    )
    if request.dynamic_queue_feed:
        queue_feed_cursor, queue_total_enqueued, queue_enqueued_identities = publish_dynamic_process_queue_jobs(
            queue_dir,
            ordered_queue_items,
            request,
            deps,
        )
    else:
        queue_feed_cursor, queue_total_enqueued, queue_enqueued_identities = publish_static_process_queue_jobs(
            queue_dir,
            request.all_files,
            deps,
        )
    return ProcessQueueSetupOutput(
        ordered_queue_items=ordered_queue_items,
        queue_feed_cursor=queue_feed_cursor,
        queue_enqueued_identities=queue_enqueued_identities,
        queue_total_enqueued=queue_total_enqueued,
    )
