from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result


def test_inmemory_retry_recovery_uses_injected_worker_result_contract():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    recovery_source = (scheduler_root / "queue" / "inmemory_retry_recovery.py").read_text(encoding="utf-8")
    failure_result_source = (scheduler_root / "queue" / "inmemory_retry_failure_result.py").read_text(encoding="utf-8")
    assert "contracts.result_record import make_worker_error_result" not in recovery_source
    assert "contracts.result_record import make_worker_error_result" not in failure_result_source
    assert "build_worker_error_result(" in recovery_source
    assert "worker_error_result(path, error)" in failure_result_source
    assert "worker_error_result" in InMemoryRecoveryCoordinator.__dataclass_fields__


def test_runtime_setup_injects_worker_owned_error_contract():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    source = (scheduler_root / "orchestration" / "inmemory_parent_runtime_setup.py").read_text(encoding="utf-8")
    assert "make_scheduler_worker_error_result" in source
    assert "worker_error_result=make_scheduler_worker_error_result" in source
    assert make_scheduler_worker_error_result.__module__ == "Virus_Scan.scheduler.workers.result_contracts"
