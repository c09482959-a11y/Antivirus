from pathlib import Path

from Virus_Scan.scheduler.workers import inmemory_spawn, inmemory_worker_pool


def test_inmemory_worker_main_is_not_imported_by_orchestration():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    for rel in (
        "orchestration/inmemory_parent_runtime_setup.py",
        "orchestration/inmemory_parent_respawn.py",
    ):
        source = (scheduler_root / rel).read_text(encoding="utf-8")
        assert "inmemory_worker_process import run_inmemory_longlived_worker" not in source
        assert "worker_main=run_inmemory_longlived_worker" not in source


def test_inmemory_spawn_modules_own_canonical_worker_main():
    assert inmemory_worker_pool.run_inmemory_longlived_worker.__module__ == "Virus_Scan.scheduler.workers.inmemory_worker_process"
    assert inmemory_spawn.run_inmemory_longlived_worker.__module__ == "Virus_Scan.scheduler.workers.inmemory_worker_process"
    assert "worker_main" not in inmemory_spawn.InMemoryWorkerRespawnRequest.__dataclass_fields__
