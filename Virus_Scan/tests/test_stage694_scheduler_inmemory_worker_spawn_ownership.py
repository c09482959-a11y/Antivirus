from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.scheduler.orchestration import inmemory_parent_respawn

from pathlib import Path

from Virus_Scan.scheduler.orchestration import inmemory_parent_loop
from Virus_Scan.scheduler.workers.inmemory_spawn import (
    InMemoryWorkerRespawnRequest,
    InMemoryWorkerRespawnResult,
    respawn_missing_inmemory_workers,
)


def test_inmemory_worker_respawn_is_worker_owned_without_execution_wrapper():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    assert not (scheduler_root / "execution" / "inmemory_worker_respawn.py").exists()
    worker_spawn = scheduler_root / "workers" / "inmemory_spawn.py"
    assert worker_spawn.exists()
    source = (scheduler_root / "orchestration" / "inmemory_parent_respawn.py").read_text(encoding="utf-8")
    assert "Virus_Scan.scheduler.workers.inmemory_spawn" in source
    assert "Virus_Scan.scheduler.execution.inmemory_worker_respawn" not in source


def test_inmemory_worker_respawn_public_surface_is_canonical():
    assert InMemoryWorkerRespawnRequest.__module__ == "Virus_Scan.scheduler.workers.inmemory_spawn"
    assert InMemoryWorkerRespawnResult.__module__ == "Virus_Scan.scheduler.workers.inmemory_spawn"
    assert respawn_missing_inmemory_workers.__module__ == "Virus_Scan.scheduler.workers.inmemory_spawn"
    assert inmemory_parent_respawn.respawn_missing_inmemory_workers is respawn_missing_inmemory_workers


def test_inmemory_worker_respawn_returns_immutable_noop_when_no_work():
    class _Ctx:
        def Process(self, **_kwargs):
            raise AssertionError("no process should be spawned without pending/active work")

    result = respawn_missing_inmemory_workers(
        InMemoryWorkerRespawnRequest(
            ctx=_Ctx(),
            procs=[],
            pending=[],
            active={},
            target_workers=2,
            task_queue=object(),
            result_queue=object(),
            worker_config={},
            lifecycle_epoch=1,
            respawn_sequence=7,
            state_index=InMemorySchedulerStateIndex(),
            worker_metrics={},
        ),
        deterministic_process_name=lambda **_kwargs: "unused",
    )
    assert result == InMemoryWorkerRespawnResult(respawn_sequence=7, started=0)
    job_records={},
    worker_metrics={},
