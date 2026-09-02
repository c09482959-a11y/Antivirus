from __future__ import annotations

from collections import deque

from Virus_Scan.scheduler.queue.inmemory_cancel import (
    InMemoryCancelRequest,
    request_cancel_only,
)
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import publish_cancel_payload, retry_or_fail


class _FailingCancelSlots:
    def __setitem__(self, key, value):
        raise RuntimeError("cancel slot write denied")


def _lifecycle(*args, **kwargs):
    return None


def _worker_error_result(path, exc):
    return {"file": str(path), "tags": [], "error": str(exc), "scan_integrity": {}}


def test_stage753_publish_cancel_payload_returns_immutable_failure_evidence():
    result = publish_cancel_payload(
        job_id=7,
        reason="queue_worker_hard_timeout",
        generation=2,
        cancel_table=None,
        cancel_generation=_FailingCancelSlots(),
        cancel_flags=_FailingCancelSlots(),
    )

    assert result.published is False
    assert result.evidence is not None
    record = dict(result.evidence.as_record())
    assert record["stage"] == "inmemory_retry_cancel_publication"
    assert record["job_id"] == 7
    assert record["generation"] == 2
    assert record["reason"] == "queue_worker_hard_timeout"
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage753_retry_or_fail_records_cancel_publication_failure_in_retry_history():
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
        cancel_table=None,
        cancel_generation=_FailingCancelSlots(),
        cancel_flags=_FailingCancelSlots(),
        lifecycle_recorder=_lifecycle,
        worker_error_result=_worker_error_result,
        pid=55,
    )

    assert result.retried is True
    record = job_records[1]
    history = tuple(record.get("history") or ())
    assert any(item.get("action") == "retry_cancel_publication_failed" for item in history)
    assert any(item.get("cancel_publication_failed") is True for item in history)
    assert pending


def test_stage753_retry_exhaustion_projects_cancel_publication_failure_into_worker_result():
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
        cancel_table=None,
        cancel_generation=_FailingCancelSlots(),
        cancel_flags=_FailingCancelSlots(),
        lifecycle_recorder=_lifecycle,
        worker_error_result=_worker_error_result,
        pid=55,
    )

    assert result.retried is False
    output = results["sample.bin"]
    integrity = output["scan_integrity"]
    assert output["retry_cancel_publication_failed"] is True
    assert integrity["retry_cancel_publication_failed"] is True
    assert integrity["queue_failure"] is True
    assert integrity["allow_learning"] is False
    assert 1 in failed
    assert 1 in terminal


def test_stage753_cancel_only_records_cancel_publication_failure_in_job_record():
    job_records = {3: {"file": "sample.bin", "attempt": 0, "state": "running", "history": ()}}
    result = request_cancel_only(InMemoryCancelRequest(
        job_records=job_records,
        terminal=set(),
        job_id=3,
        reason="queue_worker_progress_stalled",
        cancel_table=None,
        cancel_generation=_FailingCancelSlots(),
        cancel_flags=_FailingCancelSlots(),
        cancel_stall_poison_mask=3,
        pid=55,
    ))

    assert result is True
    record = job_records[3]
    assert record["cancel_publication_failed"] is True
    assert record["cancel_publication_evidence"]["replay_must_reproduce"] is True
    history = tuple(record.get("history") or ())
    assert any(item.get("cancel_publication_failed") is True for item in history)
