import inspect

from Virus_Scan.scheduler.queue import quarantine as queue_quarantine
from Virus_Scan.scheduler.queue import authority as queue_authority


def test_active_claim_protection_owned_by_queue_authority():
    source = inspect.getsource(queue_authority.process_queue_active_claim_is_protected)
    assert "active_claim_is_protected" in source
    assert "pid_is_alive" in source
    assert "_queue_missing_worker_liveness" in source
    assert "check_process_queue_worker_liveness" not in inspect.getsource(queue_authority)
    assert not hasattr(queue_quarantine, "_queue_active_claim_is_protected")


def test_process_queue_support_uses_canonical_claim_authority():
    source = inspect.getsource(queue_quarantine)
    assert "process_queue_active_claim_is_protected" in source
    assert "def _queue_active_claim_is_protected" not in source
    assert "os.kill" not in source
