"""Worker IPC lifecycle shutdown ownership.

Extracted from reconciliation so queue/recovery code does not own worker heartbeat, multiprocessing queue, or process shutdown behavior.
"""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import worker_lifecycle_exception_reason
from Virus_Scan.scheduler.workers.ipc_lifecycle_shutdown_steps import (
    join_terminated_worker_processes,
    join_worker_processes,
    record_worker_shutdown_failure,
    send_worker_shutdown_sentinels,
    terminate_live_worker_processes,
    worker_shutdown_process_list,
)
from Virus_Scan.scheduler.workers.ipc_lifecycle_shutdown_support import close_inactive_worker_processes
from Virus_Scan.scheduler.workers.ipc_lifecycle_common import (
    record_method_rejection,
    stop_worker_heartbeat,
    worker_queue_method,
)
from typing import Iterable

def close_owned_ipc_queue(queue: object, *, join_thread: bool = False, failure_recorder: object = None) -> dict[str, object]:
    """Close a scheduler-owned multiprocessing queue through one explicit path."""
    join_requested = 1 if join_thread is True else 0
    status: dict[str, object] = {"cancel_join_thread": False, "closed": False, "joined": False, "errors": []}

    def _record(label: str, exc: Exception) -> None:
        status["errors"].append({"stage": label, "error": worker_lifecycle_exception_reason(exc)})
        if callable(failure_recorder):
            try:
                failure_recorder(label, exc)
            except RECOVERABLE_RUNTIME_ERRORS as recorder_exc:
                status["errors"].append({"stage": str.__add__(label, "_recorder_failed"), "error": worker_lifecycle_exception_reason(recorder_exc)})

    if queue is None:
        return status
    cancel_join_thread, cancel_reason = worker_queue_method(queue, "cancel_join_thread")
    if cancel_reason:
        record_method_rejection(status, "queue_cancel_join_thread_rejected", cancel_reason, failure_recorder=failure_recorder)
        return status
    if not bool(join_requested) and cancel_join_thread is not None:
        try:
            cancel_join_thread()
            status["cancel_join_thread"] = True
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            _record("queue_cancel_join_thread_failed", exc)
    close_queue, close_reason = worker_queue_method(queue, "close")
    if close_reason:
        record_method_rejection(status, "queue_close_rejected", close_reason, failure_recorder=failure_recorder)
        return status
    if close_queue is not None:
        try:
            close_queue()
            status["closed"] = True
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            _record("queue_close_failed", exc)
    join_queue, join_reason = worker_queue_method(queue, "join_thread")
    if join_reason:
        record_method_rejection(status, "queue_join_thread_rejected", join_reason, failure_recorder=failure_recorder)
        return status
    if bool(join_requested) and join_queue is not None:
        try:
            join_queue()
            status["joined"] = True
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            _record("queue_join_thread_failed", exc)
    return status

def shutdown_worker_processes(
    processes: Iterable[object], *, task_queue: object = None, sentinels: int | None = None,
    exit_grace_sec: float = 15.0, terminate: bool = True, post_terminate_join_sec: float = 1.0,
    failure_recorder: object = None,
) -> dict[str, object]:
    """Own deterministic shutdown of scheduler worker processes."""
    summary: dict[str, object] = {
        "sentinels": 0,
        "joined": 0,
        "terminated": 0,
        "post_terminate_joined": 0,
        "closed": 0,
        "alive_after": 0,
        "errors": [],
    }
    procs = worker_shutdown_process_list(processes, summary)
    terminate_requested = 1 if terminate is True else 0
    send_worker_shutdown_sentinels(
        task_queue=task_queue,
        procs=procs,
        sentinels=sentinels,
        summary=summary,
        failure_recorder=failure_recorder,
    )
    join_worker_processes(
        procs=procs,
        exit_grace_sec=exit_grace_sec,
        summary=summary,
        failure_recorder=failure_recorder,
    )
    terminated_procs = terminate_live_worker_processes(
        procs=procs,
        terminate_requested=terminate_requested,
        summary=summary,
        failure_recorder=failure_recorder,
    )
    join_terminated_worker_processes(
        terminated_procs=terminated_procs,
        post_terminate_join_sec=post_terminate_join_sec,
        summary=summary,
        failure_recorder=failure_recorder,
    )
    close_inactive_worker_processes(
        procs=procs,
        summary=summary,
        failure_recorder=failure_recorder,
        record_failure=lambda label, exc: record_worker_shutdown_failure(summary, failure_recorder, label, exc),
    )
    return summary


__all__ = (
    "close_owned_ipc_queue",
    "shutdown_worker_processes",
    "stop_worker_heartbeat",
)
