from pathlib import Path


def test_stage715_worker_lifecycle_surfaces_are_worker_owned():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    deleted_execution_surfaces = [
        scheduler_root / "execution" / "worker_lifecycle.py",
        scheduler_root / "execution" / "worker_dispatch.py",
        scheduler_root / "execution" / "worker_output_publication.py",
        scheduler_root / "execution" / "inmemory_worker_result_publication.py",
        scheduler_root / "execution" / "inmemory_worker_job.py",
        scheduler_root / "execution" / "inmemory_heartbeat_flags.py",
        scheduler_root / "execution" / "inmemory_lifecycle_policy.py",
        scheduler_root / "execution" / "process_queue_worker_pool.py",
        scheduler_root / "execution" / "lifecycle_controller.py",
        scheduler_root / "runtime" / "inmemory_worker_pool.py",
        scheduler_root / "workers" / "output_publication.py",
    ]
    for surface in deleted_execution_surfaces:
        assert not surface.exists(), f"stale non-worker worker-lifecycle surface remains: {surface}"

    worker_surfaces = [
        scheduler_root / "workers" / "cleanup.py",
        scheduler_root / "workers" / "child_result_publication.py",
        scheduler_root / "workers" / "inmemory_result_publication.py",
        scheduler_root / "workers" / "inmemory_worker_pool.py",
        scheduler_root / "workers" / "inmemory_worker_job.py",
        scheduler_root / "workers" / "inmemory_heartbeat_flags.py",
        scheduler_root / "workers" / "inmemory_lifecycle_policy.py",
        scheduler_root / "workers" / "process_queue_worker_pool.py",
        scheduler_root / "workers" / "spawn_dispatch.py",
    ]
    for surface in worker_surfaces:
        assert surface.exists(), f"worker-owned surface missing: {surface}"

    neutral_publication_owner = scheduler_root / "internal" / "output_publication.py"
    assert neutral_publication_owner.exists(), (
        f"neutral shared publication owner missing: {neutral_publication_owner}"
    )


def test_stage715_callers_use_worker_owned_lifecycle_modules():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    all_source = "\n".join(path.read_text(encoding="utf-8") for path in scheduler_root.rglob("*.py"))
    forbidden_imports = [
        "Virus_Scan.scheduler.execution.worker_lifecycle",
        "Virus_Scan.scheduler.execution.worker_dispatch",
        "Virus_Scan.scheduler.execution.worker_output_publication",
        "Virus_Scan.scheduler.workers.output_publication",
        "Virus_Scan.scheduler.execution.inmemory_worker_result_publication",
        "Virus_Scan.scheduler.execution.inmemory_worker_job",
        "Virus_Scan.scheduler.execution.inmemory_heartbeat_flags",
        "Virus_Scan.scheduler.execution.inmemory_lifecycle_policy",
        "Virus_Scan.scheduler.execution.process_queue_worker_pool",
        "Virus_Scan.scheduler.runtime.inmemory_worker_pool",
    ]
    for forbidden in forbidden_imports:
        assert forbidden not in all_source
    assert "Virus_Scan.scheduler.workers.cleanup" in all_source
    assert "Virus_Scan.scheduler.workers.inmemory_worker_job" in all_source
    assert "Virus_Scan.scheduler.workers.process_queue_worker_pool" in all_source
    assert "Virus_Scan.scheduler.internal.output_publication" in all_source
