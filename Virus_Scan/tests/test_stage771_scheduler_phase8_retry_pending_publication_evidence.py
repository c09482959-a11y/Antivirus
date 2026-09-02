from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from collections import deque

from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


class RejectingPending(deque):
    def appendleft(self, _item):
        raise RuntimeError("pending queue unavailable")


class RejectingResults(dict):
    def __setitem__(self, _key, _value):
        raise RuntimeError("result publication unavailable")


class Journal:
    def record(self, *_args, **_kwargs):
        return None


def _worker_error_result(path, error):
    return {"file": str(path), "error": str(error), "scan_integrity": {"file_failed": True}}


def test_retry_pending_publication_failure_records_queue_evidence_and_fails_job():
    job_records = {5: {"file": "sample.bin", "attempt": 0, "history": ()}}
    active = {5: object()}
    failed = set()
    terminal = set()
    results = {}

    decision = retry_or_fail(
        job_records=job_records,
        active=active,
        pending=RejectingPending(),
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=5,
        reason="worker_timeout",
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=_worker_error_result,
        pid=31337,
    )

    assert decision.retried is False
    assert decision.completed_delta == 1
    assert 5 in failed
    assert 5 in terminal
    assert decision.evidence
    assert decision.evidence[0]["stage"] == "inmemory_retry_pending_publication"
    assert decision.evidence[0]["final_json_must_record"] is True
    record = job_records[5]
    assert record["retry_pending_publication_failed"] is True
    assert record["retry_pending_publication_evidence"]["stage"] == "inmemory_retry_pending_publication"
    assert record["state"] == "failed"
    result = results["sample.bin"]
    assert result["retry_pending_publication_failed"] is True
    assert result["scan_integrity"]["retry_pending_publication_failed"] is True
    assert result["scan_integrity"]["queue_failure"] is True


def test_retry_pending_publication_result_write_failure_is_also_returned_as_evidence():
    job_records = {6: {"file": "sample.bin", "attempt": 0, "history": ()}}
    failed = set()
    terminal = set()

    decision = retry_or_fail(
        job_records=job_records,
        active={6: object()},
        pending=RejectingPending(),
        results=RejectingResults(),
        failed=failed,
        terminal=terminal,
        job_id=6,
        reason="worker_timeout",
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=_worker_error_result,
        pid=31337,
    )

    stages = tuple(item["stage"] for item in decision.evidence)
    assert "inmemory_retry_pending_publication" in stages
    assert "inmemory_retry_result_publication" in stages
    assert job_records[6]["retry_result_publication_failed"] is True
    assert 6 in failed
    assert 6 in terminal


def test_recovery_coordinator_preserves_pending_publication_evidence():
    coordinator = InMemoryRecoveryCoordinator(
        job_records={0: {"file": "a.bin", "attempt": 0, "history": ()}},
        active={0: object()},
        pending=RejectingPending(),
        results={},
        failed=set(),
        terminal=set(),
        lifecycle_journal=Journal(),
        state_index=InMemorySchedulerStateIndex(),
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        cancel_stall_poison_mask=0,
        total_files=1,
        worker_error_result=_worker_error_result,
    )

    retried = coordinator.retry_or_fail(0, "worker_timeout", pid=99)

    assert retried is False
    assert coordinator.completed == 1
    assert coordinator.retry_evidence_snapshot()
    assert coordinator.retry_evidence_snapshot()[0]["stage"] == "inmemory_retry_pending_publication"
