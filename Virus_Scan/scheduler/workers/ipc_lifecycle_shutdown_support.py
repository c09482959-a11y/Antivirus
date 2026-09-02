"""Shutdown cleanup helpers for scheduler worker IPC lifecycle."""
from __future__ import annotations

from collections.abc import Iterable, MutableMapping
from typing import Callable

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.workers.ipc_lifecycle_common import record_method_rejection, worker_process_method


def close_inactive_worker_processes(
    *,
    procs: Iterable[object],
    summary: MutableMapping[str, object],
    failure_recorder: object,
    record_failure: Callable[[str, Exception], None],
) -> None:
    for proc in procs:
        try:
            is_alive, alive_reason = worker_process_method(proc, "is_alive")
            if alive_reason:
                record_method_rejection(summary, "worker_final_alive_check_rejected", alive_reason, failure_recorder=failure_recorder)
                alive = False
            else:
                alive = bool(is_alive()) if is_alive is not None else False
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_failure("worker_final_alive_check_failed", exc)
            alive = False
        if alive:
            summary["alive_after"] += 1
            continue
        try:
            join_proc, join_reason = worker_process_method(proc, "join")
            if join_reason:
                record_method_rejection(summary, "worker_final_join_rejected", join_reason, failure_recorder=failure_recorder)
            elif join_proc is not None:
                join_proc(timeout=0.0)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_failure("worker_final_join_failed", exc)
        try:
            close_proc, close_reason = worker_process_method(proc, "close")
            if close_reason:
                record_method_rejection(summary, "worker_close_rejected", close_reason, failure_recorder=failure_recorder)
            elif close_proc is not None:
                close_proc()
                summary["closed"] += 1
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_failure("worker_close_failed", exc)


__all__ = ("close_inactive_worker_processes",)
