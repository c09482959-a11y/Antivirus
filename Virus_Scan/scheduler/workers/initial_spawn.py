"""Worker-owned initial process-queue spawn policy.

This module owns initial worker-pool publication for process queues. It keeps
initial elastic target sampling, minimum worker enforcement, launch pacing, and
spawn-id accounting out of execution/orchestration modules while preserving
immutable state boundaries.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple, immutable_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.workers.process_queue_spawn_evidence import ProcessQueueWorkerSpawnFailureEvidence


@dataclass(frozen=True)
class ProcessQueueInitialSpawnRequest:
    elastic_scheduler: bool
    elastic_min_workers: int
    process_count: int
    requested_process_count: int
    queue_dir: object
    next_worker_spawn_id: int


@dataclass(frozen=True)
class ProcessQueueInitialSpawnDependencies:
    io_adjusted_elastic_target: Callable[[int, int, object], tuple[int, object, object]]
    spawn_worker: Callable[[int], bool]
    launch_delay: Callable[[], float]
    sleep: Callable[[float], object]
    log_info: Callable[[str], object]
    report_suppressed: Callable[[str, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True)
class ProcessQueueInitialSpawnOutput:
    next_worker_spawn_id: int
    initial_cpu_sample: object
    initial_io_sample: object
    initial_spawn_target: int
    worker_spawn_failures: tuple[ProcessQueueWorkerSpawnFailureEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "initial_io_sample", immutable_value(self.initial_io_sample))
        object.__setattr__(self, "worker_spawn_failures", immutable_tuple(self.worker_spawn_failures))


def _initial_spawn_log_int(value: object, rejected_reason: str) -> int:
    parsed, reason = scheduler_int(value, default=0, minimum=0, reason=rejected_reason)
    if reason:
        return 0
    return parsed



def _initial_spawn_log_message(
    *,
    initial_spawn: object,
    process_count: object,
    initial_cpu: object,
    initial_io: object,
) -> str:
    spawn_target = _initial_spawn_log_int(initial_spawn, "initial_spawn_target_rejected")
    process_total = _initial_spawn_log_int(process_count, "initial_process_count_rejected")
    if initial_cpu is None:
        cpu_text = "n/a"
    else:
        cpu_metric, cpu_reason = no_hook_finite_float(
            initial_cpu, default=0.0, minimum=0.0, reason="initial_cpu_rejected"
        )
        cpu_text = "n/a" if cpu_reason else float.__format__(cpu_metric, ".1f") + "%"
    if type(initial_io) is dict:
        pressure = dict.get(initial_io, "pressure")
        if pressure is True:
            pressure_text = "true"
        elif pressure is False:
            pressure_text = "false"
        else:
            pressure_text = "unknown"
        reason = dict.get(initial_io, "reason")
        reason_text = str.__str__(reason) if type(reason) is str and reason else "n/a"
    else:
        pressure_text = "unknown"
        reason_text = "n/a"
    return (
        "bulk scan elastic scheduler start: spawned_target="
        + int.__str__(spawn_target)
        + "/"
        + int.__str__(process_total)
        + " cpu="
        + cpu_text
        + " io_pressure="
        + pressure_text
        + " io_reason="
        + reason_text
    )


def publish_initial_process_queue_workers(
    request: ProcessQueueInitialSpawnRequest,
    dependencies: ProcessQueueInitialSpawnDependencies,
) -> ProcessQueueInitialSpawnOutput:
    """Spawn the initial process-queue worker set and return immutable state."""

    if request.elastic_scheduler:
        initial_target, initial_cpu, initial_io = dependencies.io_adjusted_elastic_target(
            request.process_count,
            request.requested_process_count,
            request.queue_dir,
        )
        initial_spawn = max(request.elastic_min_workers, min(request.process_count, initial_target))
    else:
        initial_cpu, initial_io = None, {"pressure": False}
        initial_spawn = request.process_count

    next_worker_spawn_id = int(request.next_worker_spawn_id)
    worker_spawn_failures: list[ProcessQueueWorkerSpawnFailureEvidence] = []
    for _ in range(int(initial_spawn)):
        if dependencies.spawn_worker(next_worker_spawn_id):
            next_worker_spawn_id += 1
            try:
                dependencies.sleep(dependencies.launch_delay())
            except dependencies.recoverable_exceptions as suppressed_exc:
                try:
                    dependencies.report_suppressed("monitor_loop_suppressed", suppressed_exc)
                except dependencies.recoverable_exceptions as reporting_exc:
                    _ = reporting_exc
        else:
            worker_spawn_failures.append(
                ProcessQueueWorkerSpawnFailureEvidence(
                    stage="process_queue.initial_spawn",
                    action="spawn_worker",
                    worker_id=next_worker_spawn_id,
                    error_category="worker_spawn_rejected",
                    error_source="ProcessQueueInitialSpawnDependencies.spawn_worker",
                    detail="spawn_worker returned False during initial worker publication",
                    fatal=False,
                )
            )
            break

    dependencies.log_info(
        _initial_spawn_log_message(
            initial_spawn=initial_spawn,
            process_count=request.process_count,
            initial_cpu=initial_cpu,
            initial_io=initial_io,
        )
    )
    return ProcessQueueInitialSpawnOutput(
        next_worker_spawn_id=next_worker_spawn_id,
        initial_cpu_sample=initial_cpu,
        initial_io_sample=initial_io,
        initial_spawn_target=int(initial_spawn),
        worker_spawn_failures=tuple(worker_spawn_failures),
    )


__all__ = (
    "ProcessQueueInitialSpawnDependencies",
    "ProcessQueueInitialSpawnOutput",
    "ProcessQueueInitialSpawnRequest",
    "publish_initial_process_queue_workers",
)
