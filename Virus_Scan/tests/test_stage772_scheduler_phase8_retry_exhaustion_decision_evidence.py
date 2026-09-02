from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from collections import deque

from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


class RejectingPending(deque):
    def appendleft(self, _item):
        raise RuntimeError("pending queue unavailable")


def test_retry_exhaustion_result_factory_failure_is_returned_as_decision_evidence():
    job_records = {7: {"file": "sample.bin", "attempt": 1, "history": ()}}
    decision = retry_or_fail(
        job_records=job_records,
        active={7: object()},
        pending=deque(),
        results={},
        failed=set(),
        terminal=set(),
        job_id=7,
        reason="queue_worker_hard_timeout",
        max_job_retries=0,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=lambda *_args: (_ for _ in ()).throw(RuntimeError("result factory unavailable")),
        pid=123,
    )

    stages = tuple(item["stage"] for item in decision.evidence)
    assert "inmemory_retry_exhaustion_result" in stages
    evidence = next(item for item in decision.evidence if item["stage"] == "inmemory_retry_exhaustion_result")
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True


def test_retry_pending_publication_result_factory_failure_preserves_both_evidence_records():
    job_records = {8: {"file": "pending.bin", "attempt": 0, "history": ()}}
    decision = retry_or_fail(
        job_records=job_records,
        active={8: object()},
        pending=RejectingPending(),
        results={},
        failed=set(),
        terminal=set(),
        job_id=8,
        reason="queue_worker_progress_stalled",
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=lambda *_args: (_ for _ in ()).throw(RuntimeError("result factory unavailable")),
        pid=456,
    )

    stages = tuple(item["stage"] for item in decision.evidence)
    assert "inmemory_retry_pending_publication" in stages
    assert "inmemory_retry_exhaustion_result" in stages


def test_recovery_coordinator_preserves_retry_exhaustion_decision_evidence():
    coordinator = InMemoryRecoveryCoordinator(
        job_records={0: {"file": "a.bin", "attempt": 1, "history": ()}},
        active={0: object()},
        pending=deque(),
        results={},
        failed=set(),
        terminal=set(),
        lifecycle_journal=type("Journal", (), {"record": lambda self, *_args, **_kwargs: None})(),
        state_index=InMemorySchedulerStateIndex(),
        max_job_retries=0,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        cancel_stall_poison_mask=0,
        total_files=1,
        worker_error_result=lambda *_args: (_ for _ in ()).throw(RuntimeError("result factory unavailable")),
    )

    retried = coordinator.retry_or_fail(0, "queue_worker_hard_timeout", pid=99)

    assert retried is False
    stages = tuple(item["stage"] for item in coordinator.retry_evidence_snapshot())
    assert "inmemory_retry_exhaustion_result" in stages
