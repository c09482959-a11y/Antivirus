"""Process-queue monitor loop mutable state construction."""
from __future__ import annotations

from dataclasses import dataclass
import time

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.orchestration.process_queue_monitor_guard import start_process_queue_monitor_guard
from Virus_Scan.scheduler.orchestration.process_queue_monitor_runtime import build_process_queue_monitor_runtime_state


@dataclass
class ProcessQueueMonitorLoopState:
    worker_pool: object
    all_files: tuple[str, ...]
    ordered_queue_items: tuple[object, ...]
    queue_feed_cursor: int
    queue_enqueued_identities: frozenset[str]
    queue_total_enqueued: int
    queue_last_feed_log: float
    raw_stage_progress_state: object
    next_worker_spawn_id: int
    had_error: bool
    timeout_retry_evidence_records: list[object]
    last_done_count: int
    last_progress_time: float
    timeout_config_evidence_records: tuple[object, ...]
    monitor_policy: object
    monitor_sleep_sec: float
    per_file_timeout_sec: float
    queue_progress_stall_sec: float
    last_accounted_total: int
    last_accounted_change_time: float
    idle_done_since: float | None
    last_integrity_repair_time: float
    last_monitor_heartbeat_time: float
    idle_grace_sec: float
    idle_notice_sec: float
    progress_interval_sec: float
    loop_guard: object
    loop_guard_state: object


def build_process_queue_monitor_loop_state(request: object) -> ProcessQueueMonitorLoopState:
    all_files = tuple(request.all_files)
    runtime_state = build_process_queue_monitor_runtime_state(
        configured_per_file_timeout_sec=request.per_file_timeout_sec
    )
    loop_guard, loop_guard_state = start_process_queue_monitor_guard(
        total_work=len(all_files),
        sleep_sec=runtime_state.monitor_sleep_sec,
        per_item_timeout_sec=runtime_state.per_file_timeout_sec,
        now=time.time(),
    )
    return ProcessQueueMonitorLoopState(
        worker_pool=request.worker_pool,
        all_files=all_files,
        ordered_queue_items=tuple(request.ordered_queue_items),
        queue_feed_cursor=request.queue_feed_cursor,
        queue_enqueued_identities=frozenset(request.queue_enqueued_identities),
        queue_total_enqueued=request.queue_total_enqueued,
        queue_last_feed_log=request.queue_last_feed_log,
        raw_stage_progress_state=immutable_mapping(request.raw_stage_progress_state),
        next_worker_spawn_id=request.next_worker_spawn_id,
        had_error=False,
        timeout_retry_evidence_records=[],
        last_done_count=-1,
        last_progress_time=0.0,
        timeout_config_evidence_records=tuple(runtime_state.timeout_config_evidence),
        monitor_policy=runtime_state.monitor_policy,
        monitor_sleep_sec=runtime_state.monitor_sleep_sec,
        per_file_timeout_sec=runtime_state.per_file_timeout_sec,
        queue_progress_stall_sec=runtime_state.queue_progress_stall_sec,
        last_accounted_total=runtime_state.last_accounted_total,
        last_accounted_change_time=runtime_state.last_accounted_change_time,
        idle_done_since=runtime_state.idle_done_since,
        last_integrity_repair_time=runtime_state.last_integrity_repair_time,
        last_monitor_heartbeat_time=runtime_state.last_monitor_heartbeat_time,
        idle_grace_sec=runtime_state.idle_grace_sec,
        idle_notice_sec=runtime_state.idle_notice_sec,
        progress_interval_sec=runtime_state.progress_interval_sec,
        loop_guard=loop_guard,
        loop_guard_state=loop_guard_state,
    )


__all__ = (
    "ProcessQueueMonitorLoopState",
    "build_process_queue_monitor_loop_state",
)
