from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_phase5_execution_and_orchestration_modules_are_bounded():
    scheduler_root = _repo_root() / "Virus_Scan" / "scheduler"
    oversized = []
    for rel in ("execution", "orchestration"):
        for path in (scheduler_root / rel).rglob("*.py"):
            line_count = len(path.read_text(encoding="utf-8").splitlines())
            if line_count > 250:
                oversized.append((path.relative_to(scheduler_root).as_posix(), line_count))
    assert oversized == []


def test_process_queue_monitor_loop_delegates_bounded_ownership():
    scheduler_root = _repo_root() / "Virus_Scan" / "scheduler"
    monitor = scheduler_root / "orchestration" / "process_queue_monitor_loop.py"
    text = monitor.read_text(encoding="utf-8")
    assert "prepare_monitor_iteration" in text
    iteration = scheduler_root / "orchestration" / "process_queue_monitor_iteration_start.py"
    iteration_text = iteration.read_text(encoding="utf-8")
    assert "recover_monitor_queue" in iteration_text
    assert "apply_monitor_scaling_and_feed" in iteration_text
    assert "reconcile_monitor_stall" in text
    assert "publish_monitor_progress" in text
    assert "reconcile_monitor_idle_finalization" in text
    assert "terminate_stalled_process_queue_workers" not in text
    assert "complete_inmemory_result_message" not in text


def test_inmemory_parent_loop_delegates_parent_message_and_runtime_setup():
    scheduler_root = _repo_root() / "Virus_Scan" / "scheduler"
    loop = scheduler_root / "orchestration" / "inmemory_parent_loop.py"
    text = loop.read_text(encoding="utf-8")
    assert "build_inmemory_parent_runtime" in text
    assert "handle_next_inmemory_parent_result" in text
    result = scheduler_root / "orchestration" / "inmemory_parent_result.py"
    result_text = result.read_text(encoding="utf-8")
    assert "handle_inmemory_parent_message" in result_text
    assert "run_inmemory_respawn_sweep" in text
    assert "run_inmemory_parent_maintenance" in text
    assert "complete_inmemory_result_message" not in text
    assert "enforce_inmemory_timeout_sweep" not in text
