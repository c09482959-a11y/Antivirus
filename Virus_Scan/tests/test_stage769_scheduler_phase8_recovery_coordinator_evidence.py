from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from collections import deque

from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator


class RejectingResults(dict):
    def __setitem__(self, key, value):
        raise RuntimeError("result publication rejected")


class Journal:
    def record(self, *_args, **_kwargs):
        return None


def test_recovery_coordinator_preserves_retry_decision_evidence():
    coordinator = InMemoryRecoveryCoordinator(
        job_records={0: {"file": "a.bin", "attempt": 1, "history": ()}},
        active={0: object()},
        pending=deque(),
        results=RejectingResults(),
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
        worker_error_result=lambda path, error: {"file": str(path), "error": str(error), "scan_integrity": {"file_failed": True}},
    )

    retried = coordinator.retry_or_fail(0, "worker_timeout", pid=99)

    assert retried is False
    assert coordinator.retry_evidence_snapshot()
    assert coordinator.retry_evidence_snapshot()[0]["stage"] == "inmemory_retry_result_publication"
