"""Loop owner for the long-lived in-memory worker process."""
from __future__ import annotations

import time

from Virus_Scan.scheduler.api.thread_lifecycle import SchedulerThreadPool
from Virus_Scan.scheduler.runtime.loop_guard import SchedulerLoopGuard, SchedulerLoopGuardState
from Virus_Scan.scheduler.workers.inmemory_worker_process_loop_steps import (
    InMemoryWorkerProcessLoopState,
    apply_worker_loop_guard,
    drain_or_wait_for_worker_results,
    fill_worker_thread_slots,
    publish_worker_loop_heartbeat,
)


def run_inmemory_worker_process_loop(
    *,
    task_q: object,
    result_q: object,
    cfg: object,
    local_threads: int,
    max_jobs_per_worker: int,
    cancel_table: object,
    heartbeat_table: object,
    heartbeat_interval: float,
    heartbeat_flags: object,
    worker_execution_deps: object,
    record_suppressed: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    loop_guard = SchedulerLoopGuard.for_inmemory_worker(
        max_jobs_per_worker=max_jobs_per_worker,
        heartbeat_interval=heartbeat_interval,
    )
    state = InMemoryWorkerProcessLoopState(
        active={},
        processed_jobs=0,
        stop_requested=False,
        last_heartbeat_emit=0.0,
        heartbeat_seq=0,
        loop_guard_exhausted=False,
        guard_state=SchedulerLoopGuardState.start(now=time.time(), progress_total=0),
    )
    with SchedulerThreadPool(max_workers=local_threads, thread_name_prefix="umige-worker-local") as tpool:
        while True:
            if apply_worker_loop_guard(
                state=state,
                loop_guard=loop_guard,
                record_suppressed=record_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            ):
                break
            fill_worker_thread_slots(
                state=state,
                task_q=task_q,
                result_q=result_q,
                tpool=tpool,
                local_threads=local_threads,
                worker_execution_deps=worker_execution_deps,
                worker_config=cfg,
                cancel_table=cancel_table,
                heartbeat_table=heartbeat_table,
                heartbeat_flags=heartbeat_flags,
                record_suppressed=record_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            )
            publish_worker_loop_heartbeat(
                state=state,
                cfg=cfg,
                worker_execution_deps=worker_execution_deps,
                cancel_table=cancel_table,
                heartbeat_table=heartbeat_table,
                heartbeat_flags=heartbeat_flags,
                heartbeat_interval=heartbeat_interval,
                record_suppressed=record_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            )
            if drain_or_wait_for_worker_results(
                state=state,
                result_q=result_q,
                max_jobs_per_worker=max_jobs_per_worker,
                record_suppressed=record_suppressed,
                recoverable_exceptions=recoverable_exceptions,
            ) == "break":
                break
