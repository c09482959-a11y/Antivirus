from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from collections import deque

from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


class RejectingResultsOnSecondSet(dict):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def __setitem__(self, key, value):
        self.calls += 1
        if self.calls >= 2:
            raise RuntimeError("result table update rejected")
        return super().__setitem__(key, value)


class Journal:
    def record(self, *_args, **_kwargs):
        raise RuntimeError("lifecycle journal unavailable")


def _worker_error_result(path, error):
    return {"file": str(path), "error": str(error), "scan_integrity": {"file_failed": True}}


def test_retry_pending_lifecycle_failure_is_returned_as_retry_decision_evidence():
    job_records = {1: {"file": "a.bin", "attempt": 0, "history": ()}}
    decision = retry_or_fail(
        job_records=job_records,
        active={1: object()},
        pending=deque(),
        results={},
        failed=set(),
        terminal=set(),
        job_id=1,
        reason="worker_timeout",
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: (_ for _ in ()).throw(RuntimeError("journal down")),
        worker_error_result=_worker_error_result,
        pid=22,
    )

    assert decision.retried is True
    assert decision.evidence
    assert decision.evidence[0]["stage"] == "inmemory_retry_lifecycle_publication"
    assert decision.evidence[0]["lifecycle_state"] == "retry_pending"
    assert job_records[1]["retry_lifecycle_publication_failed"] is True


def test_final_retry_lifecycle_failure_and_result_update_failure_return_evidence():
    job_records = {2: {"file": "b.bin", "attempt": 1, "history": ()}}
    results = RejectingResultsOnSecondSet()
    decision = retry_or_fail(
        job_records=job_records,
        active={2: object()},
        pending=deque(),
        results=results,
        failed=set(),
        terminal=set(),
        job_id=2,
        reason="worker_timeout",
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: (_ for _ in ()).throw(RuntimeError("journal down")),
        worker_error_result=_worker_error_result,
        pid=22,
    )

    stages = tuple(item["stage"] for item in decision.evidence)
    assert "inmemory_retry_lifecycle_publication" in stages
    assert "inmemory_retry_result_publication" in stages
    assert job_records[2]["retry_lifecycle_publication_failed"] is True
    assert job_records[2]["retry_result_publication_failed"] is True


def test_coordinator_preserves_retry_pending_lifecycle_evidence():
    coordinator = InMemoryRecoveryCoordinator(
        job_records={0: {"file": "a.bin", "attempt": 0, "history": ()}},
        active={0: object()},
        pending=deque(),
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

    assert retried is True
    assert coordinator.retry_evidence_snapshot()
    assert coordinator.retry_evidence_snapshot()[0]["stage"] == "inmemory_retry_lifecycle_publication"
    assert coordinator.retry_evidence_snapshot()[0]["lifecycle_state"] == "retry_pending"
