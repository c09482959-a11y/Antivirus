"""Shutdown/final-publication ownership for the in-memory parent loop."""
from __future__ import annotations
from Virus_Scan.contracts.env_config import float_env

import logging


from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail
from Virus_Scan.scheduler.workers.ipc_lifecycle import close_owned_ipc_queue, shutdown_worker_processes
from Virus_Scan.scheduler.workers.inmemory_shutdown import InMemoryShutdownRequest, shutdown_inmemory_runtime_state


def shutdown_inmemory_parent_runtime(*, processes: object, task_queue: object, result_queue: object, exit_grace_sec: object = None) -> None:
    if exit_grace_sec is None:
        shutdown_grace = float_env('UMIGE_INMEMORY_WORKER_EXIT_GRACE_SEC', 15.0, 0.0, None)
    elif type(exit_grace_sec) in {int, float} and type(exit_grace_sec) is not bool:
        shutdown_grace = max(0.0, float(exit_grace_sec))
    else:
        shutdown_grace = float_env('UMIGE_INMEMORY_WORKER_EXIT_GRACE_SEC', 15.0, 0.0, None)
    shutdown_inmemory_runtime_state(
        InMemoryShutdownRequest(
            processes=processes,
            task_queue=task_queue,
            result_queue=result_queue,
            shutdown_worker_processes=shutdown_worker_processes,
            close_owned_ipc_queue=close_owned_ipc_queue,
            exit_grace_sec=shutdown_grace,
            logger=logging,
            failure_recorder=record_scheduler_suppressed,
        )
    )



def shutdown_inmemory_parent_manager(*, manager: object, recoverable_exceptions: tuple[type[BaseException], ...]) -> None:
    try:
        if manager is not None:
            manager.shutdown()
    except recoverable_exceptions as exc:
        try:
            record_scheduler_suppressed('suppressed_exception', exc)
        except recoverable_exceptions as record_exc:
            log_error(
                str.__add__(
                    "scheduler manager shutdown suppression recording failed: ",
                    scheduler_error_detail(record_exc),
                )
            )
