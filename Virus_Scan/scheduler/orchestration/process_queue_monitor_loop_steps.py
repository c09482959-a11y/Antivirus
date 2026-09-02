"""Process-queue monitor loop iteration step helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
import time

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS as RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.orchestration import process_queue_monitor_guard as monitor_guard
from Virus_Scan.scheduler.orchestration.process_queue_monitor_idle import (
    MonitorIdleFinalizationRequest,
    reconcile_monitor_idle_finalization,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_iteration_start import (
    MonitorIterationStartRequest,
    prepare_monitor_iteration,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_loop_state import ProcessQueueMonitorLoopState
from Virus_Scan.scheduler.orchestration.process_queue_monitor_progress_publish import (
    MonitorProgressPublicationRequest,
    publish_monitor_progress,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_stall import MonitorStallRequest, reconcile_monitor_stall


@dataclass(frozen=True)
class ProcessQueueMonitorIterationContext:
    live: int
    counts: Mapping[str, int]
    file_done_count: int
    file_failed_count: int
    file_active_count: int
    file_pending_count: int
    raw_live: int
    accounted_total: int
    now: float
    elastic_cpu_sample: object


def begin_monitor_iteration(request: object, state: ProcessQueueMonitorLoopState) -> tuple[ProcessQueueMonitorIterationContext, bool]:
    iteration_start = prepare_monitor_iteration(
        MonitorIterationStartRequest(
            worker_pool=state.worker_pool,
            queue_dir=request.queue_dir,
            all_files=state.all_files,
            ordered_queue_items=state.ordered_queue_items,
            raw_stage_progress_state=state.raw_stage_progress_state,
            progress_stall_sec=state.queue_progress_stall_sec,
            per_file_timeout_sec=state.per_file_timeout_sec,
            last_integrity_repair_time=state.last_integrity_repair_time,
            elastic_scheduler=request.elastic_scheduler,
            process_count=request.process_count,
            requested_process_count=request.requested_process_count,
            queue_feed_cursor=state.queue_feed_cursor,
            next_worker_spawn_id=state.next_worker_spawn_id,
            dynamic_queue_feed=request.dynamic_queue_feed,
            queue_total_enqueued=state.queue_total_enqueued,
            queue_enqueued_identities=state.queue_enqueued_identities,
            queue_last_feed_log=state.queue_last_feed_log,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        )
    )
    state.raw_stage_progress_state = immutable_mapping(iteration_start.raw_stage_progress_state)
    state.last_integrity_repair_time = iteration_start.last_integrity_repair_time
    state.next_worker_spawn_id = iteration_start.next_worker_spawn_id
    state.queue_feed_cursor = iteration_start.queue_feed_cursor
    state.queue_total_enqueued = iteration_start.queue_total_enqueued
    state.queue_enqueued_identities = frozenset(iteration_start.queue_enqueued_identities)
    state.queue_last_feed_log = iteration_start.queue_last_feed_log
    state.timeout_retry_evidence_records.extend(tuple(iteration_start.stale_recovery_evidence))
    if iteration_start.stale_recovery_evidence:
        state.had_error = True
    counts = iteration_start.counts
    accounted_total = int(
        iteration_start.file_done_count
        + iteration_start.file_failed_count
        + counts["raw_done"]
        + counts["raw_failed"]
    )
    now = time.time()
    state.loop_guard_state, state.had_error, guard_stop = monitor_guard.apply_process_queue_monitor_guard(
        state.loop_guard,
        state.loop_guard_state,
        iteration_start,
        monitor_guard.ProcessQueueMonitorGuardApplyRequest(
            now=now,
            accounted_total=accounted_total,
            evidence_records=state.timeout_retry_evidence_records,
            had_error=state.had_error,
        ),
    )
    return (
        ProcessQueueMonitorIterationContext(
            live=iteration_start.live_workers,
            counts=counts,
            file_done_count=iteration_start.file_done_count,
            file_failed_count=iteration_start.file_failed_count,
            file_active_count=iteration_start.file_active_count,
            file_pending_count=iteration_start.file_pending_count,
            raw_live=iteration_start.raw_live,
            accounted_total=accounted_total,
            now=now,
            elastic_cpu_sample=iteration_start.elastic_cpu_sample,
        ),
        guard_stop,
    )


def apply_monitor_stall_step(request: object, state: ProcessQueueMonitorLoopState, context: ProcessQueueMonitorIterationContext) -> None:
    stall_output = reconcile_monitor_stall(
        MonitorStallRequest(
            worker_pool=state.worker_pool,
            live_workers=context.live,
            file_active_count=context.file_active_count,
            file_pending_count=context.file_pending_count,
            raw_live=context.raw_live,
            accounted_total=context.accounted_total,
            last_accounted_total=state.last_accounted_total,
            last_accounted_change_time=state.last_accounted_change_time,
            now=context.now,
            queue_progress_stall_sec=state.queue_progress_stall_sec,
            queue_dir=request.queue_dir,
            raw_stage_progress_state=state.raw_stage_progress_state,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        )
    )
    state.last_accounted_total = stall_output.last_accounted_total
    state.last_accounted_change_time = stall_output.last_accounted_change_time
    state.raw_stage_progress_state = immutable_mapping(stall_output.raw_stage_progress_state)
    state.timeout_retry_evidence_records.extend(tuple(stall_output.stall_escalation_evidence))
    if stall_output.stall_escalation_evidence:
        state.had_error = True


def apply_monitor_progress_step(request: object, state: ProcessQueueMonitorLoopState, context: ProcessQueueMonitorIterationContext) -> None:
    progress_output = publish_monitor_progress(
        MonitorProgressPublicationRequest(
            worker_pool=state.worker_pool,
            partial_output_path=request.partial_output_path,
            file_done_count=context.file_done_count,
            file_failed_count=context.file_failed_count,
            file_active_count=context.file_active_count,
            file_pending_count=context.file_pending_count,
            raw_live=context.raw_live,
            raw_done=context.counts["raw_done"],
            raw_failed=context.counts["raw_failed"],
            live_workers=context.live,
            total_files=len(state.all_files),
            progress_every=request.progress_every,
            last_done_count=state.last_done_count,
            last_progress_time=state.last_progress_time,
            progress_interval_sec=state.progress_interval_sec,
            last_monitor_heartbeat_time=state.last_monitor_heartbeat_time,
            monitor_heartbeat_sec=state.monitor_policy.monitor_heartbeat_sec,
            accounted_total=context.accounted_total,
            elastic_cpu_sample=context.elastic_cpu_sample,
            now=context.now,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        )
    )
    state.last_done_count = progress_output.last_done_count
    state.last_progress_time = progress_output.last_progress_time
    state.last_monitor_heartbeat_time = progress_output.last_monitor_heartbeat_time
    partial_output_evidence = tuple(progress_output.partial_output_evidence)
    if partial_output_evidence:
        state.timeout_retry_evidence_records.extend(partial_output_evidence)
        state.had_error = True


def should_stop_for_idle_state(request: object, state: ProcessQueueMonitorLoopState, context: ProcessQueueMonitorIterationContext) -> bool:
    idle_output = reconcile_monitor_idle_finalization(
        MonitorIdleFinalizationRequest(
            worker_pool=state.worker_pool,
            queue_dir=request.queue_dir,
            outputs_dir=request.outputs_dir,
            all_files=state.all_files,
            ordered_queue_items=state.ordered_queue_items,
            queue_feed_cursor=state.queue_feed_cursor,
            file_pending_count=context.file_pending_count,
            file_active_count=context.file_active_count,
            raw_live=context.raw_live,
            file_done_count=context.file_done_count,
            file_failed_count=context.file_failed_count,
            live_workers=context.live,
            idle_done_since=state.idle_done_since,
            now=context.now,
            idle_grace_sec=state.idle_grace_sec,
            idle_notice_sec=state.idle_notice_sec,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        )
    )
    state.idle_done_since = idle_output.idle_done_since
    state.idle_notice_sec = idle_output.idle_notice_sec
    state.had_error = state.had_error or idle_output.had_error
    return bool(idle_output.should_stop)


__all__ = ("ProcessQueueMonitorIterationContext", "apply_monitor_progress_step", "apply_monitor_stall_step", "begin_monitor_iteration", "should_stop_for_idle_state")
