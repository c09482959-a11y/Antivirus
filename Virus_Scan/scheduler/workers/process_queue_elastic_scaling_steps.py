"""Bounded process-queue elastic scaling target and retire substeps."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.workers.process_queue_elastic_no_hook import (
    elastic_error_category,
    elastic_error_detail,
    elastic_float_or_none,
    elastic_int,
    elastic_io_sample,
    elastic_log_message,
)
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling_fields import (
    ElasticScaleInputs,
    ElasticScaleStepResult,
    disabled_elastic_io_sample,
    elastic_scale_failure,
)
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling_spawn import (
    spawn_elastic_workers,
)
from Virus_Scan.scheduler.workers.process_queue_spawn_evidence import (
    ProcessQueueWorkerSpawnFailureEvidence,
)


def sample_elastic_target(
    inputs: ElasticScaleInputs,
    queue_dir: object,
    dependencies: object,
) -> tuple[int, float | None, Mapping[str, object], tuple[ProcessQueueWorkerSpawnFailureEvidence, ...]]:
    target_value, cpu_value, sampled_io = dependencies.io_adjusted_target(
        inputs.process_count,
        inputs.requested_process_count,
        queue_dir,
    )
    elastic_target_workers, target_issue = elastic_int(
        target_value,
        replacement=inputs.process_count,
        reason="process_queue_elastic_target_rejected",
    )
    elastic_cpu_sample, cpu_issue = elastic_float_or_none(
        cpu_value,
        minimum=0.0,
        reason="process_queue_elastic_cpu_sample_rejected",
    )
    elastic_io_sample_value, io_issue = elastic_io_sample(sampled_io)
    failures = tuple(
        elastic_scale_failure(
            action,
            issue,
            "ProcessQueueElasticScaleDependencies.io_adjusted_target",
            "elastic scaling dependency output rejected before caller-owned hooks",
        )
        for action, issue in (
            ("target_workers", target_issue),
            ("cpu_sample", cpu_issue),
            ("io_sample", io_issue),
        )
        if issue
    )
    return elastic_target_workers, elastic_cpu_sample, elastic_io_sample_value, failures


def live_elastic_work(inputs: ElasticScaleInputs) -> int:
    remaining_feed = max(0, inputs.ordered_queue_count - inputs.queue_feed_cursor)
    return inputs.file_pending_count + inputs.file_active_count + inputs.raw_live + remaining_feed


def request_elastic_worker_retire(
    inputs: ElasticScaleInputs,
    queue_dir: object,
    dependencies: object,
    elastic_target_workers: int,
    elastic_cpu_sample: float | None,
    elastic_io_sample_value: Mapping[str, object],
) -> tuple[ProcessQueueWorkerSpawnFailureEvidence, ...]:
    retire_count = min(inputs.live_workers - elastic_target_workers, max(1, inputs.live_workers // 4))
    made_value = dependencies.request_worker_retire(queue_dir, retire_count)
    made, made_issue = elastic_int(
        made_value,
        replacement=0,
        minimum=0,
        reason="process_queue_elastic_retire_count_rejected",
    )
    if made_issue:
        return (elastic_scale_failure(
            "request_worker_retire",
            made_issue,
            "ProcessQueueElasticScaleDependencies.request_worker_retire",
            "elastic scaling retire result rejected before caller-owned hooks",
        ),)
    if made > 0:
        dependencies.log_info(elastic_log_message(
            action_text="requested_idle_retire",
            amount=made,
            live=inputs.live_workers,
            process_count=inputs.process_count,
            target=elastic_target_workers,
            cpu_sample=elastic_cpu_sample,
            io_sample=elastic_io_sample_value,
        ))
    return ()


def run_elastic_scale_steps(
    inputs: ElasticScaleInputs,
    queue_dir: object,
    dependencies: object,
) -> ElasticScaleStepResult:
    failures = inputs.worker_spawn_failures
    target = inputs.process_count
    cpu_sample = None
    io_sample_value = disabled_elastic_io_sample()
    live = inputs.live_workers
    next_worker_spawn_id = inputs.next_worker_spawn_id
    try:
        target, cpu_sample, io_sample_value, target_failures = sample_elastic_target(
            inputs,
            queue_dir,
            dependencies,
        )
        failures += target_failures
        live_work_now = live_elastic_work(inputs)
        if live_work_now > 0 and live < target:
            live, next_worker_spawn_id, spawn_failures = spawn_elastic_workers(
                inputs,
                dependencies,
                target,
                cpu_sample,
                io_sample_value,
            )
            failures += spawn_failures
        elif live > target and inputs.file_pending_count <= max(1, target):
            failures += request_elastic_worker_retire(
                inputs,
                queue_dir,
                dependencies,
                target,
                cpu_sample,
                io_sample_value,
            )
    except dependencies.recoverable_exceptions as exc:
        detail = elastic_error_detail(exc)
        failures += (elastic_scale_failure(
            "elastic_scaling",
            elastic_error_category(exc),
            "apply_process_queue_elastic_scaling",
            detail,
        ),)
        dependencies.log_error("elastic process queue scheduler failed: " + detail)
    return ElasticScaleStepResult(live, next_worker_spawn_id, target, cpu_sample, io_sample_value, failures)


__all__ = (
    "live_elastic_work",
    "request_elastic_worker_retire",
    "run_elastic_scale_steps",
    "sample_elastic_target",
)
