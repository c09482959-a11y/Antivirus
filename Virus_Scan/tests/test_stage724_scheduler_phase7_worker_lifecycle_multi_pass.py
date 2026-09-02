import inspect
import Virus_Scan.scheduler.orchestration.process_queue_child_mode as child_mode

from Virus_Scan.scheduler.workers.inmemory_worker_assignment import parse_inmemory_worker_task
from Virus_Scan.scheduler.workers.process_queue_child_failure import build_child_failure_result
from Virus_Scan.scheduler.workers.process_queue_child_job import ProcessQueueChildJobRequest
from Virus_Scan.scheduler.orchestration.process_queue_child_mode import ProcessQueueChildModeRequest


def test_stage724_invalid_inmemory_assignment_is_reported():
    reported = []
    task = parse_inmemory_worker_task(
        object(),
        recoverable_exceptions=(Exception,),
        invalid_item_reporter=lambda item, exc: reported.append((item, exc)),
    )
    assert task is None
    assert reported


def test_stage724_process_queue_child_mode_delegates_worker_lifecycle():
    src = inspect.getsource(child_mode)
    assert "process_queue_child_job" in src
    assert "_umige_start_claim_heartbeat" not in src
    assert "_finish_process_queue_job" not in src
    assert "build_child_worker_error_result" not in src


def test_stage724_child_worker_failure_result_carries_failure_evidence():
    result, failure_info = build_child_failure_result(
        "sample.bin",
        RuntimeError("boom"),
        stage="stage724_test",
        job={"worker_id": "w1", "attempt": 2},
    )
    assert result["queue_failure"] is True
    assert result["scan_integrity"]["file_failed"] is True
    assert result["scan_integrity"]["had_degraded_stage"] is True
    assert result["failure_info"]["stage"] == "stage724_test"
    assert failure_info["attempt"] == 2


def test_stage724_phase7_request_contracts_are_immutable():
    assert getattr(ProcessQueueChildJobRequest, "__dataclass_params__").frozen is True
    assert getattr(ProcessQueueChildModeRequest, "__dataclass_params__").frozen is True
