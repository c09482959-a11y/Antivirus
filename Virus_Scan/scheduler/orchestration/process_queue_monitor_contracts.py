"""Immutable process-queue monitor-loop contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int, scheduler_text

if TYPE_CHECKING:
    from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
    from pathlib import Path


@dataclass(frozen=True)
class ProcessQueueMonitorLoopRequest:
    queue_dir: Path
    outputs_dir: Path
    worker_pool: ProcessQueueParentWorkerPool
    all_files: tuple[str, ...]
    ordered_queue_items: tuple[object, ...]
    queue_feed_cursor: int
    queue_enqueued_identities: frozenset[str]
    queue_total_enqueued: int
    queue_last_feed_log: float
    raw_stage_progress_state: object
    process_count: int
    requested_process_count: int
    dynamic_queue_feed: bool
    elastic_scheduler: bool
    next_worker_spawn_id: int
    progress_every: int
    partial_output_path: str | Path | None
    per_file_timeout_sec: float

    def __post_init__(self) -> None:
        queue_feed_cursor, _cursor_reason = scheduler_int(
            self.queue_feed_cursor,
            default=0,
            minimum=0,
            reason="process_queue_monitor_cursor_rejected",
        )
        queue_total_enqueued, _total_reason = scheduler_int(
            self.queue_total_enqueued,
            default=0,
            minimum=0,
            reason="process_queue_monitor_total_enqueued_rejected",
        )
        queue_last_feed_log, _last_log_reason = scheduler_float(
            self.queue_last_feed_log,
            default=0.0,
            minimum=0.0,
            reason="process_queue_monitor_last_feed_log_rejected",
        )
        process_count, _process_reason = scheduler_int(
            self.process_count,
            default=0,
            minimum=0,
            reason="process_queue_monitor_process_count_rejected",
        )
        requested_process_count, _requested_reason = scheduler_int(
            self.requested_process_count,
            default=0,
            minimum=0,
            reason="process_queue_monitor_requested_count_rejected",
        )
        dynamic_queue_feed, _dynamic_reason = scheduler_bool(
            self.dynamic_queue_feed,
            default=False,
            reason="process_queue_monitor_dynamic_feed_rejected",
        )
        elastic_scheduler, _elastic_reason = scheduler_bool(
            self.elastic_scheduler,
            default=False,
            reason="process_queue_monitor_elastic_scheduler_rejected",
        )
        next_worker_spawn_id, _spawn_reason = scheduler_int(
            self.next_worker_spawn_id,
            default=0,
            minimum=0,
            reason="process_queue_monitor_next_worker_spawn_id_rejected",
        )
        progress_every, _progress_reason = scheduler_int(
            self.progress_every,
            default=1,
            minimum=1,
            reason="process_queue_monitor_progress_every_rejected",
        )
        per_file_timeout_sec, _timeout_reason = scheduler_float(
            self.per_file_timeout_sec,
            default=0.0,
            minimum=0.0,
            reason="process_queue_monitor_per_file_timeout_rejected",
        )
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "ordered_queue_items", immutable_tuple(self.ordered_queue_items))
        queue_enqueued_identities: set[str] = set()
        for index, item in enumerate(no_hook_sequence_items(self.queue_enqueued_identities)):
            text, identity_reason = scheduler_text(
                item,
                unsupported_reason="process_queue_monitor_identity_rejected",
            )
            if identity_reason == "" and text:
                queue_enqueued_identities.add(text)
                continue
            queue_enqueued_identities.add("unsupported_queue_identity_" + int.__str__(index))
        object.__setattr__(self, "queue_feed_cursor", queue_feed_cursor)
        object.__setattr__(self, "queue_enqueued_identities", frozenset(queue_enqueued_identities))
        object.__setattr__(self, "queue_total_enqueued", queue_total_enqueued)
        object.__setattr__(self, "queue_last_feed_log", queue_last_feed_log)
        object.__setattr__(self, "process_count", process_count)
        object.__setattr__(self, "requested_process_count", requested_process_count)
        object.__setattr__(self, "dynamic_queue_feed", dynamic_queue_feed)
        object.__setattr__(self, "elastic_scheduler", elastic_scheduler)
        object.__setattr__(self, "next_worker_spawn_id", next_worker_spawn_id)
        object.__setattr__(self, "progress_every", progress_every)
        object.__setattr__(self, "per_file_timeout_sec", per_file_timeout_sec)


@dataclass(frozen=True)
class ProcessQueueMonitorLoopResult:
    had_error: bool
    timeout_retry_evidence: tuple[object, ...] = ()
    timeout_config_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        had_error, _had_error_reason = scheduler_bool(
            self.had_error,
            default=False,
            reason="process_queue_monitor_had_error_rejected",
        )
        object.__setattr__(self, "had_error", had_error)
        object.__setattr__(self, "timeout_retry_evidence", immutable_tuple(self.timeout_retry_evidence))
        object.__setattr__(self, "timeout_config_evidence", immutable_tuple(self.timeout_config_evidence))
