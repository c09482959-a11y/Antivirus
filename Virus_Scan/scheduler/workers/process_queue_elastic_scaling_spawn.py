"""Bounded process-queue elastic scaling spawn substeps."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.workers.process_queue_elastic_no_hook import (
    elastic_bool,
    elastic_error_category,
    elastic_error_detail,
    elastic_float_or_none,
    elastic_log_message,
)
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling_fields import (
    ElasticScaleInputs,
    elastic_scale_failure,
)
from Virus_Scan.scheduler.workers.process_queue_spawn_evidence import (
    ProcessQueueWorkerSpawnFailureEvidence,
)


def spawn_elastic_workers(
    inputs: ElasticScaleInputs,
    dependencies: object,
    elastic_target_workers: int,
    elastic_cpu_sample: float | None,
    elastic_io_sample_value: Mapping[str, object],
) -> tuple[int, int, tuple[ProcessQueueWorkerSpawnFailureEvidence, ...]]:
    desired_live = max(0, min(elastic_target_workers, inputs.process_count))
    to_spawn = max(0, min(desired_live - inputs.live_workers, inputs.process_count - inputs.live_workers))
    live = inputs.live_workers
    next_worker_spawn_id = inputs.next_worker_spawn_id
    spawned = 0
    failures: list[ProcessQueueWorkerSpawnFailureEvidence] = []
    for _index in range(max(0, to_spawn)):
        spawn_result = dependencies.spawn_worker(next_worker_spawn_id)
        accepted, accepted_issue = elastic_bool(
            spawn_result,
            default=False,
            reason="process_queue_elastic_spawn_result_rejected",
        )
        if not accepted:
            failures.append(elastic_scale_failure(
                "spawn_worker",
                accepted_issue or "worker_spawn_rejected",
                "ProcessQueueElasticScaleDependencies.spawn_worker",
                "spawn_worker did not return an accepted exact scheduler bool during elastic scaling",
                next_worker_spawn_id,
            ))
            break
        spawned += 1
        next_worker_spawn_id += 1
        try:
            delay, delay_issue = elastic_float_or_none(
                dependencies.respawn_delay(dependencies.env, dependencies.recoverable_exceptions),
                minimum=0.0,
                reason="process_queue_elastic_respawn_delay_rejected",
            )
            if delay_issue:
                failures.append(elastic_scale_failure(
                    "respawn_delay",
                    delay_issue,
                    "ProcessQueueElasticScaleDependencies.respawn_delay",
                    "elastic scaling respawn delay rejected before caller-owned hooks",
                    next_worker_spawn_id,
                ))
            else:
                dependencies.sleep(0.0 if delay is None else delay)
        except dependencies.recoverable_exceptions as suppressed_exc:
            try:
                dependencies.report_suppressed("monitor_loop_suppressed", suppressed_exc)
            except dependencies.recoverable_exceptions as reporting_exc:
                failures.append(elastic_scale_failure(
                    "report_suppressed",
                    elastic_error_category(reporting_exc),
                    "ProcessQueueElasticScaleDependencies.report_suppressed",
                    elastic_error_detail(reporting_exc),
                    next_worker_spawn_id,
                ))
    if spawned:
        live += spawned
        dependencies.log_info(elastic_log_message(
            action_text="scaled_up",
            amount=spawned,
            live=live,
            process_count=inputs.process_count,
            target=elastic_target_workers,
            cpu_sample=elastic_cpu_sample,
            io_sample=elastic_io_sample_value,
        ))
    return live, next_worker_spawn_id, tuple(failures)


__all__ = ("spawn_elastic_workers",)
