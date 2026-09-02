"""Worker-owned in-memory process pool startup.

This module owns process construction/startup for the in-memory scheduler. It does
not assign jobs, execute scans, own timeout policy, or reconcile results.
"""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text

from Virus_Scan.scheduler.workers.inmemory_worker_process import run_inmemory_longlived_worker


@dataclass(frozen=True)
class InMemoryWorkerPoolStartupResult:
    processes: tuple[object, ...]
    started: int

    def __post_init__(self) -> None:
        if self.processes is None:
            processes = ()
        else:
            items = no_hook_sequence_items(self.processes)
            processes = () if items is None else tuple(items)
        object.__setattr__(self, "processes", processes)


def start_inmemory_worker_pool(
    *,
    context: object,
    worker_count: int,
    task_queue: object,
    result_queue: object,
    worker_config: object,
    name_prefix: str = 'umige-inmem',
) -> InMemoryWorkerPoolStartupResult:
    processes = []
    worker_total, _worker_total_reason = scheduler_int(
        worker_count,
        minimum=0,
        reason="inmemory_worker_pool_count_rejected",
    )
    safe_name_prefix, _name_prefix_reason = scheduler_text(
        name_prefix,
        replacement_text="umige-inmem",
        unsupported_reason="inmemory_worker_pool_name_prefix_rejected",
    )
    for index in range(worker_total):
        process = context.Process(
            target=run_inmemory_longlived_worker,
            args=(task_queue, result_queue, worker_config),
            name=str.__add__(safe_name_prefix, str.__add__('-', str.rjust(int.__str__(index), 3, '0'))),
        )
        process.daemon = False
        process.start()
        processes.append(process)
    return InMemoryWorkerPoolStartupResult(processes=tuple(processes), started=len(processes))
