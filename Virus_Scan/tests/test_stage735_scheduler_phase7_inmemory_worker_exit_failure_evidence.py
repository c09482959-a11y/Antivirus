from collections import deque

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


def test_inmemory_worker_exit_exhaustion_records_worker_failure_evidence():
    job_records = {7: {"file": "sample.bin", "attempt": 1, "history": []}}
    active = {7: {"pid": 1234}}
    pending = deque()
    results = {}
    failed = set()
    terminal = set()
    lifecycle = []

    def worker_error_result(path, exc):
        return {"file": path, "queue_failure": True, "scan_integrity": {}}

    decision = retry_or_fail(
        job_records=job_records,
        active=active,
        pending=pending,
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=7,
        reason="worker_exit",
        max_job_retries=1,
        cancel_table=None,
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda request: lifecycle.append((request.job_id, request.attempt, request.transition)),
        worker_error_result=worker_error_result,
        pid=1234,
    )

    assert decision.completed_delta == 1
    result = results["sample.bin"]
    integrity = result["scan_integrity"]
    assert integrity["inmemory_worker_failure_evidence"]["reason"] == "worker_exit"
    assert integrity["inmemory_worker_exit_evidence"]["worker_pid"] == 1234
    assert 7 in failed
    assert 7 in terminal
