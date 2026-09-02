from __future__ import annotations

from pathlib import Path


def test_stage707_worker_process_and_child_console_not_execution_owned():
    root = Path(__file__).resolve().parents[1]
    assert not (root / "scheduler" / "execution" / "inmemory_worker_process.py").exists()
    assert not (root / "scheduler" / "execution" / "child_console.py").exists()
    assert (root / "scheduler" / "workers" / "inmemory_worker_process.py").exists()
    assert (root / "scheduler" / "runtime" / "child_console.py").exists()


def test_stage707_phase5_execution_orchestration_files_stay_bounded():
    root = Path(__file__).resolve().parents[1] / "scheduler"
    offenders: list[str] = []
    for folder in (root / "execution", root / "orchestration"):
        for path in folder.glob("*.py"):
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) > 200:
                offenders.append(f"{path.relative_to(root)}:{len(lines)}")
    assert offenders == []


def test_stage707_startup_and_monitor_contracts_have_canonical_owners():
    root = Path(__file__).resolve().parents[1] / "scheduler"
    startup = (root / "orchestration" / "process_queue_startup.py").read_text(encoding="utf-8")
    monitor = (root / "orchestration" / "process_queue_monitor_loop.py").read_text(encoding="utf-8")
    runtime_setup = (root / "orchestration" / "inmemory_parent_runtime_setup.py").read_text(encoding="utf-8")
    assert "prepare_process_queue_startup_admission" in startup
    assert "repair_process_queue_startup_integrity" in startup
    assert "publish_process_queue_startup_workers" in startup
    assert "build_process_queue_monitor_runtime_state" in monitor
    assert "class InMemoryParentRuntimeSetupRequest" not in runtime_setup
    assert "class InMemoryParentRuntimeSetupResult" not in runtime_setup
