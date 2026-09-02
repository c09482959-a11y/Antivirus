"""Bounded process-queue elastic scaling field parsing."""
from __future__ import annotations

from typing import Mapping, NamedTuple

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling_field_steps import (
    elastic_scale_failure,
    parse_elastic_queue_count_fields,
    parse_elastic_worker_count_fields,
)
from Virus_Scan.scheduler.workers.process_queue_spawn_evidence import (
    ProcessQueueWorkerSpawnFailureEvidence,
)


class ElasticScaleInputs(NamedTuple):
    live_workers: int
    next_worker_spawn_id: int
    process_count: int
    requested_process_count: int
    ordered_queue_count: int
    queue_feed_cursor: int
    file_pending_count: int
    file_active_count: int
    raw_live: int
    enabled: bool
    worker_spawn_failures: tuple[ProcessQueueWorkerSpawnFailureEvidence, ...]


class ElasticScaleStepResult(NamedTuple):
    live_workers: int
    next_worker_spawn_id: int
    elastic_target_workers: int
    elastic_cpu_sample: float | None
    elastic_io_sample: Mapping[str, object]
    worker_spawn_failures: tuple[ProcessQueueWorkerSpawnFailureEvidence, ...]


def disabled_elastic_io_sample() -> Mapping[str, object]:
    return immutable_mapping((("pressure", False), ("reason", "disabled")))


def parse_elastic_scale_inputs(request: object) -> ElasticScaleInputs:
    worker_fields = parse_elastic_worker_count_fields(request)
    queue_fields = parse_elastic_queue_count_fields(request)
    return ElasticScaleInputs(
        worker_fields.live_workers,
        worker_fields.next_worker_spawn_id,
        worker_fields.process_count,
        worker_fields.requested_process_count,
        queue_fields.ordered_queue_count,
        queue_fields.queue_feed_cursor,
        queue_fields.file_pending_count,
        queue_fields.file_active_count,
        queue_fields.raw_live,
        worker_fields.enabled,
        worker_fields.worker_spawn_failures,
    )


__all__ = (
    "ElasticScaleInputs",
    "ElasticScaleStepResult",
    "disabled_elastic_io_sample",
    "elastic_scale_failure",
    "parse_elastic_scale_inputs",
)
