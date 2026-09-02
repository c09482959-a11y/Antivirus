from pathlib import Path

from Virus_Scan.scheduler.orchestration.scheduler_file_execution_context import build_scheduler_file_execution_dependencies
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result


def test_scheduler_file_execution_uses_worker_owned_error_contract():
    deps = build_scheduler_file_execution_dependencies()
    assert deps.make_worker_error_result is make_scheduler_worker_error_result


def test_orchestration_does_not_import_contract_worker_error_directly():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    for rel in (
        "orchestration/scheduler_file_execution_context.py",
        "orchestration/process_queue_monitor_idle.py",
        "orchestration/scheduler_runner.py",
    ):
        source = (scheduler_root / rel).read_text(encoding="utf-8")
        assert "make_worker_error_result as _contract_worker_error_result" not in source
