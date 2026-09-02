from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from collections import deque

from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


class _Journal:
    def record(self, *args, **kwargs):
        return {"recorded": True, "args": args, "kwargs": kwargs}


def _worker_error_result(path, error):
    return {
        "file": str(path),
        "classification": "ERROR",
        "scan_integrity": {"allow_learning": False},
    }


def test_stage777_retry_or_fail_terminal_job_returns_evidence_not_clean_noop():
    job_records = {5: {"file": "terminal.bin", "attempt": 3, "state": "failed"}}
    decision = retry_or_fail(
        job_records=job_records,
        active={},
        pending=deque(),
        results={},
        failed={5},
        terminal={5},
        job_id=5,
        reason="queue_worker_hard_timeout",
        max_job_retries=1,
        cancel_table={},
        cancel_generation={},
        cancel_flags={},
        lifecycle_recorder=lambda _request: None,
        worker_error_result=_worker_error_result,
        pid=99,
    )

    assert decision.retried is False
    assert decision.completed_delta == 0
    assert decision.evidence
    record = decision.evidence[0]
    assert record["stage"] == "inmemory_retry_terminal_already"
    assert record["job_id"] == 5
    assert record["generation"] == 3
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage777_recovery_coordinator_projects_terminal_retry_evidence():
    job_records = {5: {"file": "terminal.bin", "attempt": 3, "state": "failed"}}
    coordinator = InMemoryRecoveryCoordinator(
        job_records=job_records,
        active={},
        pending=deque(),
        results={},
        failed={5},
        terminal={5},
        lifecycle_journal=_Journal(),
        state_index=InMemorySchedulerStateIndex(),
        max_job_retries=1,
        cancel_table={},
        cancel_generation={},
        cancel_flags={},
        cancel_stall_poison_mask=0,
        total_files=1,
        worker_error_result=_worker_error_result,
    )

    retried = coordinator.retry_or_fail(5, "queue_worker_hard_timeout", pid=99)

    assert retried is False
    assert len(coordinator.retry_evidence_snapshot()) == 1
    assert coordinator.retry_evidence_snapshot()[0]["stage"] == "inmemory_retry_terminal_already"
