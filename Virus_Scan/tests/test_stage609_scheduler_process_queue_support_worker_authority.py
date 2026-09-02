import inspect

from Virus_Scan.scheduler.queue import issue_reporting as queue_issue_reporting
from Virus_Scan.scheduler.queue import integrity_pipeline as queue_integrity_pipeline
from Virus_Scan.scheduler.queue import claim_protection as queue_claim_protection


def test_process_queue_support_uses_injected_worker_liveness_boundary_without_local_wrapper():
    source = inspect.getsource(queue_claim_protection.process_queue_active_claim_is_protected)
    assert "pid_is_alive" in source
    assert "check_process_queue_worker_liveness" not in source
    assert "os.kill" not in source
    assert "queue_active_claim_worker_liveness_dependency_missing" in inspect.getsource(queue_claim_protection._queue_missing_worker_liveness)
    assert not hasattr(queue_claim_protection, "check_process_queue_worker_liveness")
    assert not hasattr(queue_issue_reporting, "_worker_pid_is_alive")
    assert not hasattr(queue_issue_reporting, "_umige_pid_is_alive")
    assert not hasattr(queue_integrity_pipeline, "_worker_pid_is_alive")
    assert not hasattr(queue_integrity_pipeline, "_umige_pid_is_alive")
