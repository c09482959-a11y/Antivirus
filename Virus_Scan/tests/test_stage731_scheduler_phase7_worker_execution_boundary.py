from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_stage731_worker_owned_execution_boundary_modules_moved():
    root = _repo_root()
    scheduler = root / "Virus_Scan" / "scheduler"

    old_execution_modules = (
        scheduler / "execution" / "process_queue_elastic.py",
        scheduler / "execution" / "inmemory_job_dispatch.py",
        scheduler / "execution" / "inmemory_job_accounting.py",
        scheduler / "execution" / "inmemory_dispatch_backpressure.py",
        scheduler / "execution" / "inmemory_capacity.py",
    )
    for path in old_execution_modules:
        assert not path.exists(), f"worker lifecycle/dispatch ownership remained in execution: {path}"

    required_worker_modules = (
        scheduler / "workers" / "process_queue_elastic_scaling.py",
        scheduler / "workers" / "inmemory_job_dispatch.py",
        scheduler / "ownership" / "inmemory_scheduler_state_index.py",
        scheduler / "workers" / "inmemory_dispatch_backpressure.py",
        scheduler / "workers" / "inmemory_capacity_plan.py",
    )
    for path in required_worker_modules:
        assert path.exists(), f"scheduler-owned boundary module missing: {path}"

    assert not (scheduler / "workers" / "inmemory_job_accounting.py").exists()


def test_stage731_no_scheduler_domain_imports_worker_internals_except_orchestration_and_workers():
    root = _repo_root()
    scheduler = root / "Virus_Scan" / "scheduler"
    offenders: list[str] = []
    for path in scheduler.rglob("*.py"):
        rel = path.relative_to(scheduler)
        if rel.parts[0] in {"workers", "orchestration"}:
            continue
        text = path.read_text(encoding="utf-8")
        if "Virus_Scan.scheduler.workers" in text:
            offenders.append(str(rel))
    assert offenders == []


def test_stage731_worker_modules_do_not_exceed_phase7_size_target():
    root = _repo_root()
    worker_dir = root / "Virus_Scan" / "scheduler" / "workers"
    oversized: list[str] = []
    for path in worker_dir.glob("*.py"):
        if path.name == "__init__.py":
            continue
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        if line_count > 200:
            oversized.append(f"{path.name}:{line_count}")
    assert oversized == []
