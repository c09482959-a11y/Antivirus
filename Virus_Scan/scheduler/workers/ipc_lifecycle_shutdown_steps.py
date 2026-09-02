"""Bounded shutdown steps for scheduler worker IPC lifecycle."""
from __future__ import annotations

from typing import Iterable
import time

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import worker_lifecycle_exception_reason
from Virus_Scan.scheduler.workers.ipc_lifecycle_common import (
    record_method_rejection,
    worker_lifecycle_float,
    worker_lifecycle_int,
    worker_process_method,
)


def worker_shutdown_process_list(processes: Iterable[object], summary: dict[str, object]) -> list[object]:
    if processes is None:
        return []
    if type(processes) is list:
        return list(processes)
    if type(processes) is tuple:
        return list(processes)
    summary["errors"].append({
        "stage": "worker_process_collection_rejected",
        "error": "unsupported_worker_process_collection",
    })
    return []


def record_worker_shutdown_failure(
    summary: dict[str, object],
    failure_recorder: object,
    label: str,
    exc: Exception,
) -> None:
    summary["errors"].append({"stage": label, "error": worker_lifecycle_exception_reason(exc)})
    if callable(failure_recorder):
        try:
            failure_recorder(label, exc)
        except RECOVERABLE_RUNTIME_ERRORS as recorder_exc:
            summary["errors"].append({
                "stage": str.__add__(label, "_recorder_failed"),
                "error": worker_lifecycle_exception_reason(recorder_exc),
            })


def send_worker_shutdown_sentinels(
    *,
    task_queue: object,
    procs: list[object],
    sentinels: int | None,
    summary: dict[str, object],
    failure_recorder: object,
) -> None:
    if task_queue is None:
        return
    count = len(procs) if sentinels is None else max(0, worker_lifecycle_int(sentinels, len(procs)))
    for _ in range(count):
        try:
            task_queue.put(None, timeout=0.5)
            summary["sentinels"] += 1
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_worker_shutdown_failure(summary, failure_recorder, "worker_shutdown_sentinel_failed", exc)


def join_worker_processes(
    *,
    procs: list[object],
    exit_grace_sec: float,
    summary: dict[str, object],
    failure_recorder: object,
) -> None:
    deadline = time.time() + max(0.0, worker_lifecycle_float(exit_grace_sec, 15.0))
    for proc in procs:
        try:
            remaining = max(0.0, deadline - time.time())
            join_proc, join_reason = worker_process_method(proc, "join")
            if join_reason:
                record_method_rejection(summary, "worker_join_rejected", join_reason, failure_recorder=failure_recorder)
            elif join_proc is not None:
                join_proc(timeout=remaining)
                summary["joined"] += 1
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_worker_shutdown_failure(summary, failure_recorder, "worker_join_failed", exc)


def terminate_live_worker_processes(
    *,
    procs: list[object],
    terminate_requested: int,
    summary: dict[str, object],
    failure_recorder: object,
) -> list[object]:
    terminated_procs: list[object] = []
    if not bool(terminate_requested):
        return terminated_procs
    for proc in procs:
        try:
            is_alive, alive_reason = worker_process_method(proc, "is_alive")
            if alive_reason:
                record_method_rejection(summary, "worker_alive_check_rejected", alive_reason, failure_recorder=failure_recorder)
                alive = False
            else:
                alive = bool(is_alive()) if is_alive is not None else False
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_worker_shutdown_failure(summary, failure_recorder, "worker_alive_check_failed", exc)
            alive = False
        if alive:
            try:
                terminate_proc, terminate_reason = worker_process_method(proc, "terminate")
                if terminate_reason:
                    record_method_rejection(summary, "worker_terminate_rejected", terminate_reason, failure_recorder=failure_recorder)
                elif terminate_proc is not None:
                    terminate_proc()
                    terminated_procs.append(proc)
                    summary["terminated"] += 1
            except RECOVERABLE_RUNTIME_ERRORS as exc:
                record_worker_shutdown_failure(summary, failure_recorder, "worker_terminate_failed", exc)
    return terminated_procs


def join_terminated_worker_processes(
    *,
    terminated_procs: list[object],
    post_terminate_join_sec: float,
    summary: dict[str, object],
    failure_recorder: object,
) -> None:
    post_terminate_timeout = max(0.0, worker_lifecycle_float(post_terminate_join_sec, 1.0))
    for proc in terminated_procs:
        try:
            join_proc, join_reason = worker_process_method(proc, "join")
            if join_reason:
                record_method_rejection(
                    summary,
                    "worker_post_terminate_join_rejected",
                    join_reason,
                    failure_recorder=failure_recorder,
                )
            elif join_proc is not None:
                join_proc(timeout=post_terminate_timeout)
                summary["post_terminate_joined"] += 1
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_worker_shutdown_failure(summary, failure_recorder, "worker_post_terminate_join_failed", exc)


__all__ = (
    "join_terminated_worker_processes",
    "join_worker_processes",
    "record_worker_shutdown_failure",
    "send_worker_shutdown_sentinels",
    "terminate_live_worker_processes",
    "worker_shutdown_process_list",
)
