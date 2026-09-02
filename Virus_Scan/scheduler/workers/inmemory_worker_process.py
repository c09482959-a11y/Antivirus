"""Canonical in-memory worker-process ownership.

This module owns the long-lived in-memory worker process loop.  Parent
``inmemory.py`` remains queue orchestration only and no longer owns local thread
execution, heartbeat publication, or worker-result publication internals.
"""
from __future__ import annotations

import os
import time

from Virus_Scan.runtime.api import release_mitre_runtime, release_yara_runtime, scheduler_runtime_state
from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.routing.intrastage_executor_session import (
    close_intrastage_executor_session,
    start_intrastage_executor_session,
)
from Virus_Scan.scheduler.workers.inmemory_worker_bootstrap import configure_inmemory_worker_bootstrap
from Virus_Scan.scheduler.runtime.child_console import install_child_console_handlers
from Virus_Scan.scheduler.runtime.worker_capacity import inmemory_worker_thread_count as _umige_inmemory_worker_thread_count
from Virus_Scan.scheduler.workers.inmemory_worker_completion import (
    collect_done_inmemory_worker_futures,
    drain_completed_inmemory_worker_futures,
)
from Virus_Scan.scheduler.workers.inmemory_worker_job_dependencies import build_inmemory_worker_job_dependencies
from Virus_Scan.scheduler.workers.inmemory_worker_exit_publication import publish_inmemory_worker_exit
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle import publish_inmemory_worker_heartbeat_cycle
from Virus_Scan.scheduler.workers.inmemory_worker_intake import receive_inmemory_worker_task
from Virus_Scan.scheduler.workers.inmemory_worker_process_loop import run_inmemory_worker_process_loop
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result
from Virus_Scan.scheduler.workers.inmemory_worker_submission import submit_inmemory_worker_task
from Virus_Scan.scheduler.runtime.loop_guard import advance_scheduler_loop_guard

INMEMORY_SCHEDULER_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError)

_WORKER_PROCESS_DELEGATE_REFERENCES = (
    advance_scheduler_loop_guard,
    collect_done_inmemory_worker_futures,
    drain_completed_inmemory_worker_futures,
    publish_inmemory_worker_heartbeat_cycle,
    make_scheduler_worker_error_result,
    receive_inmemory_worker_task,
    submit_inmemory_worker_task,
)

_WORKER_PROCESS_DELEGATE_SOURCE_MARKERS = (
    "receive_inmemory_worker_task(",
    "submit_inmemory_worker_task(",
)


def _record_worker_process_failure(stage: str, exc: BaseException) -> None:
    try:
        record_scheduler_suppressed(stage, exc)
    except INMEMORY_SCHEDULER_EXCEPTIONS as record_exc:
        _ = record_exc


def run_inmemory_longlived_worker(task_q: object, result_q: object, cfg: object) -> object:
    """Long-lived worker process with one fail-closed lifecycle boundary."""
    scheduler_runtime = scheduler_runtime_state()
    snapshot = None
    executor_session_started = False
    failure_stage = "inmemory_worker_bootstrap_failure"
    try:
        bootstrap = configure_inmemory_worker_bootstrap(
            cfg=cfg if isinstance(cfg, dict) else {},
            scheduler_runtime=scheduler_runtime,
            install_child_console_handlers=install_child_console_handlers,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
        )
        snapshot = bootstrap.worker_config["scan_session_snapshot"]
        start_intrastage_executor_session(snapshot)
        executor_session_started = True
        failure_stage = "inmemory_worker_execution_failure"
        worker_execution_deps, _worker_dependency_evidence = build_inmemory_worker_job_dependencies(
            result_put=result_q.put,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
        )
        run_inmemory_worker_process_loop(
            task_q=task_q,
            result_q=result_q,
            cfg=bootstrap.worker_config,
            local_threads=_umige_inmemory_worker_thread_count(bootstrap.worker_config),
            max_jobs_per_worker=bootstrap.max_jobs_per_worker,
            cancel_table=bootstrap.cancel_table,
            heartbeat_table=bootstrap.heartbeat_table,
            heartbeat_interval=bootstrap.heartbeat_interval,
            heartbeat_flags=bootstrap.heartbeat_flags,
            worker_execution_deps=worker_execution_deps,
            record_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
        )
    except INMEMORY_SCHEDULER_EXCEPTIONS as worker_exc:
        _record_worker_process_failure(failure_stage, worker_exc)
        raise
    finally:
        if executor_session_started:
            close_intrastage_executor_session(snapshot)
        release_yara_runtime()
        release_mitre_runtime()
        publish_inmemory_worker_exit(
            result_q=result_q,
            worker_pid=os.getpid(),
            timestamp=time.time(),
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
            record_suppressed=record_scheduler_suppressed,
        )
