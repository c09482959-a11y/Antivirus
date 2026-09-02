"""Worker-owned elastic process-queue scaling decisions and evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.workers.process_queue_elastic_no_hook import elastic_io_sample
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling_fields import (
    ElasticScaleStepResult,
    disabled_elastic_io_sample,
    parse_elastic_scale_inputs,
)
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling_steps import (
    run_elastic_scale_steps,
)
from Virus_Scan.scheduler.workers.process_queue_spawn_evidence import (
    ProcessQueueWorkerSpawnFailureEvidence,
)


@dataclass(frozen=True)
class ProcessQueueElasticScaleRequest:
    enabled: bool
    process_count: int
    requested_process_count: int
    queue_dir: object
    ordered_queue_count: int
    queue_feed_cursor: int
    file_pending_count: int
    file_active_count: int
    raw_live: int
    live_workers: int
    next_worker_spawn_id: int


@dataclass(frozen=True)
class ProcessQueueElasticScaleDependencies:
    io_adjusted_target: Callable[..., tuple[int, object, Mapping[object, object]]]
    spawn_worker: Callable[[int], bool]
    request_worker_retire: Callable[[object, int], int]
    respawn_delay: Callable[..., float]
    env: object
    recoverable_exceptions: tuple[type[BaseException], ...]
    sleep: Callable[[float], object]
    log_info: Callable[..., object]
    log_error: Callable[..., object]
    report_suppressed: Callable[..., object]


@dataclass(frozen=True)
class ProcessQueueElasticScaleOutput:
    live_workers: int
    next_worker_spawn_id: int
    elastic_target_workers: int
    elastic_cpu_sample: float | None
    elastic_io_sample: Mapping[str, object]
    worker_spawn_failures: tuple[ProcessQueueWorkerSpawnFailureEvidence, ...] = ()

    def __post_init__(self) -> None:
        frozen_io, _issue = elastic_io_sample(self.elastic_io_sample)
        object.__setattr__(self, "elastic_io_sample", frozen_io)
        if type(self.worker_spawn_failures) in {tuple, list}:
            failures = tuple(
                item
                for item in self.worker_spawn_failures
                if type(item) is ProcessQueueWorkerSpawnFailureEvidence
            )
            object.__setattr__(self, "worker_spawn_failures", failures)
        else:
            object.__setattr__(self, "worker_spawn_failures", ())


def apply_process_queue_elastic_scaling(
    request: ProcessQueueElasticScaleRequest,
    dependencies: ProcessQueueElasticScaleDependencies,
) -> ProcessQueueElasticScaleOutput:
    """Scale process-queue workers through injected worker-owned spawn/retire callbacks."""
    inputs = parse_elastic_scale_inputs(request)
    if inputs.enabled:
        result = run_elastic_scale_steps(inputs, request.queue_dir, dependencies)
    else:
        result = ElasticScaleStepResult(
            inputs.live_workers,
            inputs.next_worker_spawn_id,
            inputs.process_count,
            None,
            disabled_elastic_io_sample(),
            inputs.worker_spawn_failures,
        )
    return ProcessQueueElasticScaleOutput(
        live_workers=result.live_workers,
        next_worker_spawn_id=result.next_worker_spawn_id,
        elastic_target_workers=result.elastic_target_workers,
        elastic_cpu_sample=result.elastic_cpu_sample,
        elastic_io_sample=result.elastic_io_sample,
        worker_spawn_failures=result.worker_spawn_failures,
    )


__all__ = (
    "ProcessQueueElasticScaleDependencies",
    "ProcessQueueElasticScaleOutput",
    "ProcessQueueElasticScaleRequest",
    "apply_process_queue_elastic_scaling",
)
