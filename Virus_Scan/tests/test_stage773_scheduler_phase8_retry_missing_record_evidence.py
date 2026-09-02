from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from collections import deque

from Virus_Scan.scheduler.queue.inmemory_empty_drain import requeue_missing_after_empty_drain
from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


class _Lifecycle:
    def record(self, *_args, **_kwargs):
        return None


def _worker_error_result(path, error):
    return {"file": str(path), "error": str(error), "scan_integrity": {}}


def test_retry_or_fail_missing_job_record_returns_retry_failure_evidence():
    terminal = set()
    failed = set()
    decision = retry_or_fail(
        job_records={},
        active={},
        pending=deque(),
        results={},
        failed=failed,
        terminal=terminal,
        job_id=4,
        reason="missing_after_empty_drain",
        max_job_retries=1,
        cancel_table=None,
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=_worker_error_result,
    )

    assert decision.retried is False
    assert decision.completed_delta == 1
    assert 4 in failed
    assert 4 in terminal
    assert decision.evidence
    evidence = decision.evidence[0]
    assert evidence["stage"] == "inmemory_retry_missing_record"
    assert evidence["queue_failure"] is True
    assert evidence["retry_failure"] is True
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True


def test_recovery_coordinator_preserves_missing_record_retry_evidence():
    coordinator = InMemoryRecoveryCoordinator(
        job_records={},
        active={},
        pending=deque(),
        results={},
        failed=set(),
        terminal=set(),
        lifecycle_journal=_Lifecycle(),
        state_index=InMemorySchedulerStateIndex(),
        max_job_retries=1,
        cancel_table=None,
        cancel_generation=None,
        cancel_flags=None,
        cancel_stall_poison_mask=0,
        total_files=1,
        worker_error_result=_worker_error_result,
    )

    retried = coordinator.retry_or_fail(0, "queue_worker_hard_timeout", pid=99)

    assert retried is False
    assert coordinator.completed == 1
    assert coordinator.retry_evidence_snapshot()
    assert coordinator.retry_evidence_snapshot()[0]["stage"] == "inmemory_retry_missing_record"


def test_empty_drain_missing_record_counts_failed_now_and_preserves_evidence():
    failed = set()
    terminal = set()
    decision = requeue_missing_after_empty_drain(
        total_files=1,
        terminal=terminal,
        retry_callable=lambda job_id, reason: retry_or_fail(
            job_records={},
            active={},
            pending=deque(),
            results={},
            failed=failed,
            terminal=terminal,
            job_id=job_id,
            reason=reason,
            max_job_retries=1,
            cancel_table=None,
            cancel_generation=None,
            cancel_flags=None,
            lifecycle_recorder=lambda _request: None,
            worker_error_result=_worker_error_result,
        ),
    )

    assert decision.retried == 0
    assert decision.failed_now == 1
    assert decision.completed_delta == 1
    assert decision.evidence
    assert decision.evidence[0]["stage"] == "inmemory_retry_missing_record"


def test_retry_or_fail_duplicate_pending_returns_decision_evidence():
    job_records = {
        7: {
            "file": "duplicate.bin",
            "attempt": 1,
            "state": "pending_retry",
            "retry_pending_generation": 1,
            "retry_pending_active": True,
            "history": (),
        }
    }
    decision = retry_or_fail(
        job_records=job_records,
        active={7: {"pid": 44}},
        pending=deque(),
        results={},
        failed=set(),
        terminal=set(),
        job_id=7,
        reason="queue_worker_orphaned",
        max_job_retries=3,
        cancel_table=None,
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=_worker_error_result,
        pid=44,
    )

    assert decision.retried is False
    assert decision.completed_delta == 0
    assert decision.evidence
    assert decision.evidence[0]["stage"] == "inmemory_retry_duplicate_pending"
    assert decision.evidence[0]["final_json_must_record"] is True
    assert job_records[7]["history"][-1]["action"] == "duplicate_recovery_ignored"
