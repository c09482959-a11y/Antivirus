from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path


def _imports_from(path: str) -> list[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module]


def test_queue_claim_protection_does_not_import_worker_liveness_directly():
    modules = _imports_from("Virus_Scan/scheduler/queue/claim_protection.py")
    assert not any(module.startswith("Virus_Scan.scheduler.workers") for module in modules)
    source = read_python_file(Path("Virus_Scan/scheduler/queue/claim_protection.py"))
    assert "pid_is_alive" in source
    assert "queue_active_claim_worker_liveness_dependency_missing" in source


def test_queue_integrity_accepts_worker_liveness_callback_boundary():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/integrity_pipeline.py"))
    assert "active_claim_pid_is_alive" in source
    assert "process_queue_active_claim_is_protected(" in source
    assert "pid_is_alive=active_claim_pid_is_alive" in source


def test_stall_recovery_passes_worker_callbacks_to_queue_recovery():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/process_queue_monitor_stall.py"))
    assert "worker_liveness_checker=check_process_queue_worker_liveness" in source
    assert "worker_terminator=terminate_queue_worker_pid" in source


def test_worker_specific_execution_modules_are_worker_owned():
    assert not Path("Virus_Scan/scheduler/execution/inmemory_file_scan.py").exists()
    assert not Path("Virus_Scan/scheduler/execution/inmemory_runtime_config.py").exists()
    assert Path("Virus_Scan/scheduler/workers/inmemory_file_scan.py").exists()
    assert Path("Virus_Scan/scheduler/workers/inmemory_runtime_config.py").exists()


def test_execution_queue_timeout_do_not_import_worker_modules_directly():
    for folder in (
        Path("Virus_Scan/scheduler/execution"),
        Path("Virus_Scan/scheduler/queue"),
        Path("Virus_Scan/scheduler/timeout"),
    ):
        for path in folder.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            assert "Virus_Scan.scheduler.workers" not in source, str(path)
