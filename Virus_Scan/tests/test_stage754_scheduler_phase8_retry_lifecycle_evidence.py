from __future__ import annotations

from collections import deque

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


def _failing_lifecycle(*args, **kwargs):
    raise RuntimeError("lifecycle write denied")


def _worker_error_result(path, exc):
    return {"file": str(path), "tags": [], "error": str(exc), "scan_integrity": {}}


def test_stage754_retry_pending_lifecycle_failure_is_immutable_retry_evidence():
    job_records = {1: {"file": "sample.bin", "attempt": 0, "state": "running", "history": ()}}
    pending = deque()
    result = retry_or_fail(
        job_records=job_records,
        active={1: {"pid": 55}},
        pending=pending,
        results={},
        failed=set(),
        terminal=set(),
        job_id=1,
        reason="queue_worker_progress_stalled",
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=_failing_lifecycle,
        worker_error_result=_worker_error_result,
        pid=55,
    )

    assert result.retried is True
    assert pending
    record = job_records[1]
    assert record["retry_lifecycle_publication_failed"] is True
    evidence = record["retry_lifecycle_publication_evidence"]
    assert evidence["stage"] == "inmemory_retry_lifecycle_publication"
    assert evidence["lifecycle_state"] == "retry_pending"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    assert any(item.get("retry_lifecycle_publication_failed") is True for item in record.get("history") or ())


def test_stage754_retry_exhaustion_lifecycle_failure_projects_into_worker_result():
    job_records = {1: {"file": "sample.bin", "attempt": 1, "state": "running", "history": ()}}
    results = {}
    failed = set()
    terminal = set()
    result = retry_or_fail(
        job_records=job_records,
        active={1: {"pid": 55}},
        pending=deque(),
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=1,
        reason="queue_worker_hard_timeout",
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=_failing_lifecycle,
        worker_error_result=_worker_error_result,
        pid=55,
    )

    assert result.retried is False
    output = results["sample.bin"]
    integrity = output["scan_integrity"]
    assert output["retry_lifecycle_publication_failed"] is True
    assert integrity["retry_lifecycle_publication_failed"] is True
    assert integrity["queue_failure"] is True
    assert integrity["allow_learning"] is False
    assert job_records[1]["retry_lifecycle_publication_failed"] is True
    assert 1 in failed
    assert 1 in terminal
