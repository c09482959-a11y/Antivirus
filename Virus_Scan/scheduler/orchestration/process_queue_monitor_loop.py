"""Thin process-queue parent monitor-loop orchestration owner."""
from __future__ import annotations

import time

from Virus_Scan.scheduler.orchestration.process_queue_monitor_contracts import (
    ProcessQueueMonitorLoopRequest,
    ProcessQueueMonitorLoopResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_loop_state import build_process_queue_monitor_loop_state
from Virus_Scan.scheduler.orchestration.process_queue_monitor_guard import apply_process_queue_monitor_guard
from Virus_Scan.scheduler.orchestration.process_queue_monitor_runtime import build_process_queue_monitor_runtime_state
from Virus_Scan.scheduler.orchestration.process_queue_monitor_idle import reconcile_monitor_idle_finalization
from Virus_Scan.scheduler.orchestration.process_queue_monitor_iteration_start import prepare_monitor_iteration
from Virus_Scan.scheduler.orchestration.process_queue_monitor_progress_publish import publish_monitor_progress
from Virus_Scan.scheduler.orchestration.process_queue_monitor_stall import reconcile_monitor_stall
from Virus_Scan.scheduler.orchestration.process_queue_monitor_loop_steps import (
    apply_monitor_progress_step,
    apply_monitor_stall_step,
    begin_monitor_iteration,
    should_stop_for_idle_state,
)


_MONITOR_LOOP_DELEGATE_OWNERS = (
    build_process_queue_monitor_runtime_state,
    apply_process_queue_monitor_guard,
    prepare_monitor_iteration,
    reconcile_monitor_stall,
    publish_monitor_progress,
    reconcile_monitor_idle_finalization,
)


def monitor_process_queue(request: ProcessQueueMonitorLoopRequest) -> ProcessQueueMonitorLoopResult:
    state = build_process_queue_monitor_loop_state(request)
    while True:
        context, guard_stop = begin_monitor_iteration(request, state)
        if guard_stop:
            break
        apply_monitor_stall_step(request, state, context)
        apply_monitor_progress_step(request, state, context)
        if context.live <= 0:
            break
        if should_stop_for_idle_state(request, state, context):
            break
        time.sleep(state.monitor_sleep_sec)
    return ProcessQueueMonitorLoopResult(
        had_error=state.had_error,
        timeout_retry_evidence=tuple(state.timeout_retry_evidence_records),
        timeout_config_evidence=tuple(state.timeout_config_evidence_records),
    )
