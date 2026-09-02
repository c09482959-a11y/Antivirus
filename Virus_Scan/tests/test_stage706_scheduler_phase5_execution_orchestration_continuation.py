from pathlib import Path


def _scheduler_root() -> Path:
    return Path(__file__).resolve().parents[1] / "scheduler"


def test_stage706_raw_stage_executor_delegates_collector_dispatch():
    root = _scheduler_root()
    executor = (root / "execution" / "raw_stage_executor.py").read_text(encoding="utf-8")
    dispatch = (root / "execution" / "raw_stage_collector_dispatch.py").read_text(encoding="utf-8")
    assert "dispatch_raw_stage_collector" in executor
    assert "elif collector ==" not in executor
    assert "elif collector ==" in dispatch
    assert "report=deps.record_suppressed" in dispatch


def test_stage706_inmemory_raw_scan_is_thin_execution_coordinator():
    root = _scheduler_root()
    scan = (root / "workers" / "inmemory_raw_scan.py").read_text(encoding="utf-8")
    assert "build_inmemory_raw_plan" in scan
    assert "execute_inmemory_raw_jobs" in scan
    assert "finalize_inmemory_raw_scan_result" in scan
    assert "with deps.scheduler_thread_pool" not in scan
    body = scan.split("def scan_file_inmemory_raw", 1)[1]
    assert "remember_scan_evidence" not in body


def test_stage706_scheduler_file_job_delegates_terminal_and_analysis_paths():
    root = _scheduler_root()
    job = (root / "execution" / "scheduler_file_job.py").read_text(encoding="utf-8")
    assert "maybe_return_terminal_result" in job
    assert "execute_scheduler_file_analysis" in job
    body = job.split("def execute_scheduler_file_job", 1)[1]
    assert "analyze_file_full_observe_only" not in body
    assert len(job.splitlines()) < 180


def test_stage706_scheduler_mode_dispatch_owns_mode_selection():
    root = _scheduler_root()
    runner = (root / "orchestration" / "scheduler_runner.py").read_text(encoding="utf-8")
    dispatcher = (root / "orchestration" / "scheduler_mode_dispatch.py").read_text(encoding="utf-8")
    assert "run_scheduler_mode" in runner
    assert "run_process_queue_child_mode" in dispatcher
    assert "run_scheduler_serial_mode" in dispatcher
    assert "_run_longlived_process_queue" in dispatcher
    assert "run_process_queue_child_mode" not in runner
