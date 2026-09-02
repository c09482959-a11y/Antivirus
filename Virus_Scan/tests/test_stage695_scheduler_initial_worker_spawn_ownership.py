from __future__ import annotations

from pathlib import Path

import Virus_Scan.scheduler.workers.initial_spawn as initial_spawn_module
from Virus_Scan.scheduler.workers.initial_spawn import (
    ProcessQueueInitialSpawnDependencies,
    ProcessQueueInitialSpawnRequest,
    publish_initial_process_queue_workers,
)


def test_stage695_initial_process_spawn_is_worker_owned_without_execution_shim():
    assert Path(initial_spawn_module.__file__).name == "initial_spawn.py"
    assert not Path("Virus_Scan/scheduler/execution/process_queue_initial_spawn.py").exists()


def test_stage695_initial_process_spawn_preserves_worker_count_and_launch_pacing(tmp_path):
    spawned: list[int] = []
    slept: list[float] = []
    logs: list[str] = []

    def spawn_worker(worker_index: int) -> bool:
        spawned.append(worker_index)
        return True

    output = publish_initial_process_queue_workers(
        ProcessQueueInitialSpawnRequest(
            elastic_scheduler=False,
            elastic_min_workers=1,
            process_count=3,
            requested_process_count=3,
            queue_dir=tmp_path,
            next_worker_spawn_id=7,
        ),
        ProcessQueueInitialSpawnDependencies(
            io_adjusted_elastic_target=lambda process_count, requested, queue_dir: (process_count, None, {"pressure": False}),
            spawn_worker=spawn_worker,
            launch_delay=lambda: 0.25,
            sleep=lambda seconds: slept.append(seconds),
            log_info=lambda message: logs.append(message),
            report_suppressed=lambda stage, exc: None,
            recoverable_exceptions=(RuntimeError,),
        ),
    )

    assert spawned == [7, 8, 9]
    assert slept == [0.25, 0.25, 0.25]
    assert output.next_worker_spawn_id == 10
    assert output.initial_spawn_target == 3
    assert logs and "spawned_target=3/3" in logs[0]
