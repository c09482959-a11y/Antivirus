"""In-memory scheduler shutdown reconciliation ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class InMemoryShutdownRequest:
    processes: list[object]
    task_queue: object
    result_queue: object
    shutdown_worker_processes: Callable[..., object]
    close_owned_ipc_queue: Callable[..., object]
    exit_grace_sec: float
    logger: object
    failure_recorder: Callable[[str, BaseException], object]


@dataclass(frozen=True)
class InMemoryShutdownResult:
    worker_summary: object
    task_queue_closed: bool
    result_queue_closed: bool


def shutdown_inmemory_runtime_state(request: InMemoryShutdownRequest) -> InMemoryShutdownResult:
    summary = request.shutdown_worker_processes(
        request.processes,
        task_queue=request.task_queue,
        exit_grace_sec=float(request.exit_grace_sec),
        terminate=True,
        failure_recorder=request.failure_recorder,
    )
    if summary.get("alive_after"):
        request.logger.warning("in-memory worker shutdown left alive workers: %s", summary)
    request.close_owned_ipc_queue(
        request.task_queue,
        join_thread=False,
        failure_recorder=request.failure_recorder,
    )
    request.close_owned_ipc_queue(
        request.result_queue,
        join_thread=False,
        failure_recorder=request.failure_recorder,
    )
    return InMemoryShutdownResult(worker_summary=summary, task_queue_closed=True, result_queue_closed=True)
