"""Worker-owned in-memory process respawn policy.

The in-memory execution loop decides when more workers are required. This module
owns deterministic process creation and returns explicit respawn facts without
embedding worker spawn semantics in execution modules.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.workers.inmemory_respawn_capacity import schedulable_inmemory_worker_count
from Virus_Scan.scheduler.workers.inmemory_spawn_evidence import inmemory_owned_nonempty_decision
from Virus_Scan.scheduler.workers.inmemory_worker_process import run_inmemory_longlived_worker

_SCHEDULER_ZERO_INT = 0



def _owned_int(
    value: object,
    *,
    default_value: int = _SCHEDULER_ZERO_INT,
    minimum: int | None = None,
    reason: str,
) -> int:
    parsed, parse_reason = scheduler_int(value, default=default_value, minimum=minimum, reason=reason)
    if parse_reason != "":
        return default_value
    return parsed


@dataclass(frozen=True)
class InMemoryWorkerRespawnRequest:
    ctx: object
    procs: tuple[object, ...]
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "procs", no_hook_sequence_items(self.procs))




@dataclass(frozen=True)
class InMemoryWorkerRespawnResult:
    respawn_sequence: int
    started: int
    processes: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "processes", no_hook_sequence_items(self.processes))



def respawn_missing_inmemory_workers(
    request: InMemoryWorkerRespawnRequest,
    *,
    deterministic_process_name: Callable[..., str],
) -> InMemoryWorkerRespawnResult:
    """Respawn missing in-memory workers from worker-owned spawn policy."""
    live_count = schedulable_inmemory_worker_count(
        procs=request.procs,
        worker_config=request.worker_config,
        worker_metrics=request.worker_metrics,
    )
    pending_nonempty = inmemory_owned_nonempty_decision(
        request.pending,
        field_name="pending_workers",
    ).nonempty
    active_nonempty = inmemory_owned_nonempty_decision(
        request.active,
        field_name="active_workers",
    ).nonempty
    queued_unstarted = request.state_index.queued_unstarted_count()
    if (not pending_nonempty) and (not active_nonempty) and queued_unstarted <= 0:
        return InMemoryWorkerRespawnResult(
            _owned_int(
                request.respawn_sequence,
                default_value=_SCHEDULER_ZERO_INT,
                minimum=0,
                reason="inmemory_respawn_sequence_rejected",
            ),
            0,
        )
    target_workers = _owned_int(
        request.target_workers,
        default_value=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_respawn_target_workers_rejected",
    )
    missing = max(0, target_workers - live_count)
    respawn_sequence = _owned_int(
        request.respawn_sequence,
        default_value=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_respawn_sequence_rejected",
    )
    started = 0
    started_processes = []
    for _ in range(missing):
        respawn_sequence += 1
        proc = request.ctx.Process(
            target=run_inmemory_longlived_worker,
            args=(request.task_queue, request.result_queue, request.worker_config),
            name=deterministic_process_name(
                prefix="umige-inmem-r",
                epoch=request.lifecycle_epoch,
                sequence=respawn_sequence,
            ),
        )
        proc.daemon = False
        proc.start()
        started_processes.append(proc)
        started += 1
    return InMemoryWorkerRespawnResult(respawn_sequence, started, tuple(started_processes))


__all__ = (
    "InMemoryWorkerRespawnRequest",
    "InMemoryWorkerRespawnResult",
    "respawn_missing_inmemory_workers",
)
