from __future__ import annotations

from collections import deque

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


class _FailingCancelSlots:
    def __setitem__(self, key, value):
        raise RuntimeError("cancel publication denied")


def _worker_error_result(path, error):
    return {
        "file": str(path),
        "classification": "ERROR",
        "error": str(error),
        "scan_integrity": {"allow_learning": False},
    }


def _lifecycle_recorder(*_args, **_kwargs):
    return None


def test_stage779_retry_success_returns_cancel_publication_failure_evidence():
    job_records = {
        7: {
            "file": "retry-success.bin",
            "attempt": 0,
            "state": "running",
            "history": (),
        }
    }
    pending = deque()

    decision = retry_or_fail(
        job_records=job_records,
        active={7: {"pid": 77}},
        pending=pending,
        results={},
        failed=set(),
        terminal=set(),
        job_id=7,
        reason="queue_worker_hard_timeout",
        max_job_retries=2,
        cancel_table=None,
        cancel_generation=_FailingCancelSlots(),
        cancel_flags=_FailingCancelSlots(),
        lifecycle_recorder=_lifecycle_recorder,
        worker_error_result=_worker_error_result,
        pid=77,
    )

    assert decision.retried is True
    assert pending
    stages = tuple(record.get("stage") for record in decision.evidence)
    assert "inmemory_retry_cancel_publication" in stages
    cancel_records = tuple(record for record in decision.evidence if record.get("stage") == "inmemory_retry_cancel_publication")
    assert len(cancel_records) == 1
    assert cancel_records[0]["job_id"] == 7
    assert cancel_records[0]["reason"] == "queue_worker_hard_timeout"
    assert cancel_records[0]["final_json_must_record"] is True
    assert cancel_records[0]["checkpoint_must_record"] is True
    assert cancel_records[0]["replay_must_reproduce"] is True


def test_stage779_retry_exhaustion_returns_cancel_publication_failure_evidence():
    job_records = {
        8: {
            "file": "retry-exhausted.bin",
            "attempt": 0,
            "state": "running",
            "history": (),
        }
    }
    results = {}

    decision = retry_or_fail(
        job_records=job_records,
        active={8: {"pid": 88}},
        pending=deque(),
        results=results,
        failed=set(),
        terminal=set(),
        job_id=8,
        reason="queue_worker_hard_timeout",
        max_job_retries=0,
        cancel_table=None,
        cancel_generation=_FailingCancelSlots(),
        cancel_flags=_FailingCancelSlots(),
        lifecycle_recorder=_lifecycle_recorder,
        worker_error_result=_worker_error_result,
        pid=88,
    )

    assert decision.retried is False
    assert decision.completed_delta == 1
    stages = tuple(record.get("stage") for record in decision.evidence)
    assert "inmemory_retry_cancel_publication" in stages
    cancel_records = tuple(record for record in decision.evidence if record.get("stage") == "inmemory_retry_cancel_publication")
    assert len(cancel_records) == 1
    assert cancel_records[0]["job_id"] == 8
    assert cancel_records[0]["reason"] == "queue_worker_hard_timeout"
    final_result = results["retry-exhausted.bin"]
    assert final_result["retry_cancel_publication_failed"] is True
    assert final_result["retry_cancel_publication_evidence"]["stage"] == "inmemory_retry_cancel_publication"
