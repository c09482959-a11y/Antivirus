"""Parent-side in-memory worker respawn orchestration."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import monitor_recoverable_exceptions

from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.workers.inmemory_lifecycle_policy import deterministic_worker_process_name
from Virus_Scan.scheduler.workers.inmemory_spawn import InMemoryWorkerRespawnRequest, respawn_missing_inmemory_workers


@dataclass(frozen=True)
class InMemoryRespawnSweepRequest:
    ctx: object
    procs: object
    pending: object
    active: object
    target_workers: int
    task_queue: object
    result_queue: object
    worker_config: object
    lifecycle_epoch: int
    respawn_sequence: int
    state_index: object
    worker_metrics: object
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))


@dataclass(frozen=True)
class InMemoryRespawnSweepResult:
    respawn_sequence: int
    started: int


def run_inmemory_respawn_sweep(request: InMemoryRespawnSweepRequest) -> InMemoryRespawnSweepResult:
    try:
        respawn_result = respawn_missing_inmemory_workers(
            InMemoryWorkerRespawnRequest(
                ctx=request.ctx,
                procs=request.procs,
                pending=request.pending,
                active=request.active,
                target_workers=request.target_workers,
                task_queue=request.task_queue,
                result_queue=request.result_queue,
                worker_config=request.worker_config,
                lifecycle_epoch=request.lifecycle_epoch,
                respawn_sequence=request.respawn_sequence,
                state_index=request.state_index,
                worker_metrics=request.worker_metrics,
            ),
            deterministic_process_name=deterministic_worker_process_name,
        )
        if type(respawn_result.processes) is tuple and len(respawn_result.processes) > 0 and type(request.procs) is list:
            request.procs.extend(respawn_result.processes)
        return InMemoryRespawnSweepResult(
            respawn_sequence=respawn_result.respawn_sequence,
            started=respawn_result.started,
        )
    except request.recoverable_exceptions as exc:
        log_error("in-memory worker respawn failed: " + scheduler_error_detail(exc))
        return InMemoryRespawnSweepResult(respawn_sequence=request.respawn_sequence, started=0)
