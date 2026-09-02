from __future__ import annotations

from Virus_Scan.scheduler.workers.initial_spawn import (
    ProcessQueueInitialSpawnDependencies,
    ProcessQueueInitialSpawnRequest,
    publish_initial_process_queue_workers,
)
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling import (
    ProcessQueueElasticScaleDependencies,
    ProcessQueueElasticScaleRequest,
    apply_process_queue_elastic_scaling,
)


def test_stage751_initial_spawn_rejection_returns_worker_owned_evidence(tmp_path):
    spawned: list[int] = []

    def spawn_worker(worker_id: int) -> bool:
        spawned.append(worker_id)
        return False

    output = publish_initial_process_queue_workers(
        ProcessQueueInitialSpawnRequest(
            elastic_scheduler=False,
            elastic_min_workers=1,
            process_count=2,
            requested_process_count=2,
            queue_dir=tmp_path,
            next_worker_spawn_id=9,
        ),
        ProcessQueueInitialSpawnDependencies(
            io_adjusted_elastic_target=lambda process_count, requested, queue_dir: (process_count, None, {"pressure": False}),
            spawn_worker=spawn_worker,
            launch_delay=lambda: 0.0,
            sleep=lambda seconds: None,
            log_info=lambda message: None,
            report_suppressed=lambda stage, exc: None,
            recoverable_exceptions=(RuntimeError,),
        ),
    )

    assert spawned == [9]
    assert output.next_worker_spawn_id == 9
    assert output.worker_spawn_failures
    evidence = output.worker_spawn_failures[0]
    assert evidence.stage == "process_queue.initial_spawn"
    assert evidence.action == "spawn_worker"
    assert evidence.worker_id == 9
    assert evidence.final_json_must_record is True
    assert evidence.checkpoint_must_record is True
    assert evidence.replay_must_reproduce is True
    assert evidence.as_record()["error_category"] == "worker_spawn_rejected"


def test_stage751_elastic_spawn_rejection_returns_worker_owned_evidence(tmp_path):
    spawned: list[int] = []

    def spawn_worker(worker_id: int) -> bool:
        spawned.append(worker_id)
        return False

    output = apply_process_queue_elastic_scaling(
        ProcessQueueElasticScaleRequest(
            enabled=True,
            process_count=3,
            requested_process_count=3,
            queue_dir=tmp_path,
            ordered_queue_count=4,
            queue_feed_cursor=0,
            file_pending_count=1,
            file_active_count=0,
            raw_live=0,
            live_workers=0,
            next_worker_spawn_id=4,
        ),
        ProcessQueueElasticScaleDependencies(
            io_adjusted_target=lambda process_count, requested, queue_dir: (2, None, {"pressure": False}),
            spawn_worker=spawn_worker,
            request_worker_retire=lambda queue_dir, count: 0,
            respawn_delay=lambda env, recoverable: 0.0,
            env={},
            recoverable_exceptions=(RuntimeError,),
            sleep=lambda seconds: None,
            log_info=lambda *args, **kwargs: None,
            log_error=lambda *args, **kwargs: None,
            report_suppressed=lambda *args, **kwargs: None,
        ),
    )

    assert spawned == [4]
    assert output.live_workers == 0
    assert output.next_worker_spawn_id == 4
    assert output.worker_spawn_failures
    evidence = output.worker_spawn_failures[0]
    assert evidence.stage == "process_queue.elastic_scaling"
    assert evidence.action == "spawn_worker"
    assert evidence.worker_id == 4
    assert evidence.as_record()["error_category"] == "worker_spawn_rejected"


def test_stage751_elastic_target_failure_returns_worker_owned_evidence(tmp_path):
    def fail_target(process_count: int, requested: int, queue_dir):
        raise RuntimeError("sample failed")

    output = apply_process_queue_elastic_scaling(
        ProcessQueueElasticScaleRequest(
            enabled=True,
            process_count=3,
            requested_process_count=3,
            queue_dir=tmp_path,
            ordered_queue_count=4,
            queue_feed_cursor=0,
            file_pending_count=1,
            file_active_count=0,
            raw_live=0,
            live_workers=0,
            next_worker_spawn_id=4,
        ),
        ProcessQueueElasticScaleDependencies(
            io_adjusted_target=fail_target,
            spawn_worker=lambda worker_id: True,
            request_worker_retire=lambda queue_dir, count: 0,
            respawn_delay=lambda env, recoverable: 0.0,
            env={},
            recoverable_exceptions=(RuntimeError,),
            sleep=lambda seconds: None,
            log_info=lambda *args, **kwargs: None,
            log_error=lambda *args, **kwargs: None,
            report_suppressed=lambda *args, **kwargs: None,
        ),
    )

    assert output.worker_spawn_failures
    evidence = output.worker_spawn_failures[0]
    assert evidence.stage == "process_queue.elastic_scaling"
    assert evidence.action == "elastic_scaling"
    assert evidence.error_category == "RuntimeError"
    assert evidence.as_record()["detail"] == "sample failed"
