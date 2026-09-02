from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path



def _line_count(path: str) -> int:
    return len(Path(path).read_text(encoding="utf-8").splitlines())


def test_stage702_process_queue_runner_is_thin_execution_entrypoint():
    source = read_python_file(Path("Virus_Scan/scheduler/execution/process_queue_runner.py"))
    assert _line_count("Virus_Scan/scheduler/execution/process_queue_runner.py") < 140
    assert "ProcessQueueStartupRequest" in source
    assert "ProcessQueueMonitorLoopRequest" in source
    assert "ProcessQueueCompletionRequest" in source
    assert "publish_process_queue_worker_spawn" not in source
    assert "merge_process_queue_results" not in source
    assert "while True:" not in source


def test_stage702_process_queue_orchestration_owners_exist():
    expected = [
        "Virus_Scan/scheduler/orchestration/process_queue_startup.py",
        "Virus_Scan/scheduler/orchestration/process_queue_worker_pool_state.py",
        "Virus_Scan/scheduler/orchestration/process_queue_monitor_loop.py",
        "Virus_Scan/scheduler/orchestration/process_queue_completion.py",
    ]
    for path in expected:
        assert Path(path).exists(), path


def test_stage702_scheduler_pipeline_uses_bounded_child_and_dependency_contexts():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/scheduler_runner.py"))
    assert _line_count("Virus_Scan/scheduler/orchestration/scheduler_runner.py") <= 240
    assert "run_scheduler_mode" in source
    mode = read_python_file(Path("Virus_Scan/scheduler/orchestration/scheduler_mode_dispatch.py"))
    assert "run_process_queue_child_mode" in mode
    assert "build_scheduler_file_execution_dependencies" in source
    assert "while True:" not in source
    assert "execute_inmemory_raw_stage_job" not in source
