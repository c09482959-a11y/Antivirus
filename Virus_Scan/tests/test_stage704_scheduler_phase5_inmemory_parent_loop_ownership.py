from pathlib import Path


def test_inmemory_parent_loop_moved_to_orchestration_owner():
    root = Path(__file__).resolve().parents[1] / "scheduler"
    assert not (root / "execution" / "inmemory_longlived_queue.py").exists()
    owner = root / "orchestration" / "inmemory_parent_loop.py"
    assert owner.exists()
    text = owner.read_text(encoding="utf-8")
    assert "def _run_longlived_process_queue" in text
    assert "build_inmemory_parent_runtime" in text


def test_scheduler_mode_dispatch_uses_orchestration_inmemory_parent_loop():
    dispatcher = Path(__file__).resolve().parents[1] / "scheduler" / "orchestration" / "scheduler_mode_dispatch.py"
    text = dispatcher.read_text(encoding="utf-8")
    assert "scheduler.orchestration.inmemory_parent_loop import _run_longlived_process_queue" in text
    assert "scheduler.execution.inmemory_longlived_queue" not in text


def test_scheduler_pipeline_delegates_target_planning_and_serial_mode():
    root = Path(__file__).resolve().parents[1] / "scheduler"
    pipeline = root / "orchestration" / "scheduler_runner.py"
    text = pipeline.read_text(encoding="utf-8")
    assert "plan_scheduler_targets" in text
    assert "run_scheduler_mode" in text
    mode = (root / "orchestration" / "scheduler_mode_dispatch.py").read_text(encoding="utf-8")
    assert "run_scheduler_serial_mode" in mode
    assert "collect_target_files" not in text
    assert "workload_plan_summary" not in text
