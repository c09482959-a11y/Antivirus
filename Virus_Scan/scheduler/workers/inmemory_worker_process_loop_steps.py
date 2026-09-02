"""Bounded loop steps for the long-lived in-memory worker process."""
from __future__ import annotations

import os
from dataclasses import dataclass
from queue import Empty as InMemoryTaskQueueEmpty
import time

from Virus_Scan.scheduler.api.thread_lifecycle import SchedulerThreadPool
from Virus_Scan.scheduler.runtime.loop_guard import (
    SchedulerLoopGuard,
    SchedulerLoopGuardAdvanceRequest,
    SchedulerLoopGuardState,
    advance_scheduler_loop_guard,
)
from Virus_Scan.scheduler.workers.inmemory_worker_completion import (
    InMemoryWorkerCompletionDrainRequest,
    collect_done_inmemory_worker_futures,
    drain_completed_inmemory_worker_futures,
)
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle import publish_inmemory_worker_heartbeat_cycle
from Virus_Scan.scheduler.workers.inmemory_worker_intake import (
    InMemoryWorkerTaskIntakeDependencies,
    receive_inmemory_worker_task,
)
from Virus_Scan.scheduler.workers.inmemory_worker_job import execute_inmemory_worker_job
from Virus_Scan.scheduler.workers.inmemory_worker_submission import submit_inmemory_worker_task
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result


@dataclass
class InMemoryWorkerProcessLoopState:
    active: dict[object, object]
    processed_jobs: int
    stop_requested: bool
    last_heartbeat_emit: float
    heartbeat_seq: int
    loop_guard_exhausted: bool
    guard_state: SchedulerLoopGuardState


def apply_worker_loop_guard(
    *,
    state: InMemoryWorkerProcessLoopState,
    loop_guard: SchedulerLoopGuard,
    record_suppressed: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    guard_decision = advance_scheduler_loop_guard(
        SchedulerLoopGuardAdvanceRequest(
            guard=loop_guard,
            state=state.guard_state,
            now=time.time(),
            progress_total=state.processed_jobs,
            pending_count=0,
            active_count=len(state.active),
            completed_count=state.processed_jobs,
            failed_count=0,
            worker_live_count=1,
            queue_live_count=len(state.active),
        )
    )
    state.guard_state = guard_decision.state
    if not guard_decision.exhausted or state.loop_guard_exhausted:
        return False
    state.loop_guard_exhausted = True
    try:
        record_suppressed(guard_decision.reason, RuntimeError("in-memory worker loop guard exhausted"))
    except recoverable_exceptions as guard_record_exc:
        _ = guard_record_exc
    state.stop_requested = True
    return not state.active


def fill_worker_thread_slots(
    *,
    state: InMemoryWorkerProcessLoopState,
    task_q: object,
    result_q: object,
    tpool: SchedulerThreadPool,
    local_threads: int,
    worker_execution_deps: object,
    worker_config: object,
    cancel_table: object,
    heartbeat_table: object,
    heartbeat_flags: object,
    record_suppressed: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    while not state.stop_requested and len(state.active) < local_threads:
        intake_result = receive_inmemory_worker_task(
            task_q=task_q,
            intake=InMemoryWorkerTaskIntakeDependencies(
                result_put=result_q.put,
                queue_empty_type=InMemoryTaskQueueEmpty,
                recoverable_exceptions=recoverable_exceptions,
                record_suppressed=record_suppressed,
            ),
        )
        if intake_result.queue_empty:
            break
        if intake_result.stop_requested:
            state.stop_requested = True
            break
        if intake_result.task is None:
            continue
        submit_inmemory_worker_task(
            task=intake_result.task,
            tpool=tpool,
            active=state.active,
            execute_job=execute_inmemory_worker_job,
            worker_execution_deps=worker_execution_deps,
            worker_config=worker_config,
            cancel_table=cancel_table,
            heartbeat_table=heartbeat_table,
            heartbeat_flags=heartbeat_flags,
            completed_jobs=state.processed_jobs,
            recoverable_exceptions=recoverable_exceptions,
            record_suppressed=record_suppressed,
        )


def publish_worker_loop_heartbeat(
    *,
    state: InMemoryWorkerProcessLoopState,
    cfg: object,
    worker_execution_deps: object,
    cancel_table: object,
    heartbeat_table: object,
    heartbeat_flags: object,
    heartbeat_interval: float,
    record_suppressed: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    heartbeat_result = publish_inmemory_worker_heartbeat_cycle(
        active=state.active,
        cfg=cfg if isinstance(cfg, dict) else {},
        cancel_table=cancel_table,
        heartbeat_table=heartbeat_table,
        heartbeat_flags=heartbeat_flags,
        completed_jobs=state.processed_jobs,
        cancel_requested=worker_execution_deps.cancel_requested,
        update_shared_heartbeat=worker_execution_deps.update_shared_heartbeat,
        process_id=os.getpid(),
        now_hb=time.time(),
        last_heartbeat_emit=state.last_heartbeat_emit,
        heartbeat_interval=heartbeat_interval,
        heartbeat_seq=state.heartbeat_seq,
        recoverable_exceptions=recoverable_exceptions,
        record_suppressed=record_suppressed,
    )
    state.last_heartbeat_emit = heartbeat_result.last_heartbeat_emit
    state.heartbeat_seq = heartbeat_result.heartbeat_seq
    if heartbeat_result.stop_requested:
        state.stop_requested = True


def drain_or_wait_for_worker_results(
    *,
    state: InMemoryWorkerProcessLoopState,
    result_q: object,
    max_jobs_per_worker: int,
    record_suppressed: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> str:
    if not state.active:
        return "break" if state.stop_requested else "continue"
    done_futs = collect_done_inmemory_worker_futures(state.active)
    if not done_futs:
        time.sleep(0.02)
        return "continue"
    completion_result = drain_completed_inmemory_worker_futures(
        InMemoryWorkerCompletionDrainRequest(
            done_futures=done_futs,
            active=state.active,
            result_q=result_q,
            max_jobs_per_worker=max_jobs_per_worker,
            processed_jobs=state.processed_jobs,
            worker_error_result=make_scheduler_worker_error_result,
            recoverable_exceptions=recoverable_exceptions,
            record_suppressed=record_suppressed,
        )
    )
    state.processed_jobs = completion_result.processed_jobs
    if completion_result.stop_requested:
        state.stop_requested = True
    return "continue"
