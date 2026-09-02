from pathlib import Path

from Virus_Scan.scheduler.workers import process_queue_worker_pool
from Virus_Scan.scheduler.workers.spawn import build_process_queue_worker_command
from Virus_Scan.scheduler.workers.spawn_dispatch import (
    ProcessQueueWorkerDispatchRequest,
    dispatch_process_queue_worker,
)


def test_process_queue_spawn_is_worker_owned_without_execution_wrapper():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    assert not (scheduler_root / "execution" / "process_queue_spawn.py").exists()
    worker_spawn = scheduler_root / "workers" / "spawn.py"
    assert worker_spawn.exists()
    source = (scheduler_root / "workers" / "process_queue_worker_pool.py").read_text(encoding="utf-8")
    assert "Virus_Scan.scheduler.workers.spawn_dispatch" in source
    assert not (scheduler_root / "execution" / "process_queue_worker_pool.py").exists()
    assert "Virus_Scan.scheduler.execution.process_queue_spawn" not in source


def test_worker_spawn_public_surface_is_canonical():
    assert ProcessQueueWorkerDispatchRequest.__module__ == "Virus_Scan.scheduler.workers.spawn_dispatch"
    assert build_process_queue_worker_command.__module__ == "Virus_Scan.scheduler.workers.spawn"
    assert dispatch_process_queue_worker.__module__ == "Virus_Scan.scheduler.workers.spawn_dispatch"
    assert process_queue_worker_pool.dispatch_process_queue_worker is dispatch_process_queue_worker
