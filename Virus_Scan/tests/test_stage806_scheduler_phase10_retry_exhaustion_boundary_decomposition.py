from __future__ import annotations

from collections import deque
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail
from Virus_Scan.scheduler.queue.inmemory_retry_exhaustion_integrity import attach_retry_exhaustion_integrity
from Virus_Scan.scheduler.queue.inmemory_retry_exhaustion_lifecycle import record_failed_lifecycle_evidence
from Virus_Scan.scheduler.queue.inmemory_retry_exhaustion_publication import retry_result_publication_failed


def test_stage806_retry_exhaustion_module_delegates_bounded_ownership() -> None:
    queue_root = Path("Virus_Scan/scheduler/queue")
    exhausted_source = (queue_root / "inmemory_retry_recovery_exhausted.py").read_text()

    assert "inmemory_retry_exhaustion_integrity" in exhausted_source
    assert "inmemory_retry_exhaustion_lifecycle" in exhausted_source
    assert "inmemory_retry_exhaustion_publication" in exhausted_source
    assert "def _attach_retry_exhaustion_integrity" not in exhausted_source
    assert "def _retry_result_publication_failed" not in exhausted_source
    assert "def _record_failed_lifecycle_evidence" not in exhausted_source

    assert callable(attach_retry_exhaustion_integrity)
    assert callable(record_failed_lifecycle_evidence)
    assert callable(retry_result_publication_failed)


def test_stage806_retry_exhaustion_lifecycle_failure_still_flows_into_integrity() -> None:
    job_records = {7: {"file": "sample.bin", "attempt": 1, "history": ()}}
    results = {}
    failed = set()
    terminal = set()

    decision = retry_or_fail(
        job_records=job_records,
        active={7: object()},
        pending=deque(),
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=7,
        reason="queue_worker_hard_timeout",
        max_job_retries=0,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: (_ for _ in ()).throw(RuntimeError("journal unavailable")),
        worker_error_result=lambda path, error: {"path": path, "scan_integrity": {}},
        pid=123,
    )

    assert decision.retried is False
    assert decision.completed_delta == 1
    assert failed == {7}
    assert terminal == {7}
    result = results["sample.bin"]
    assert result["retry_lifecycle_publication_failed"] is True
    assert result["retry_lifecycle_publication_evidence"]["stage"] == "inmemory_retry_lifecycle_publication"
    assert result["scan_integrity"]["retry_lifecycle_publication_failed"] is True
    assert result["scan_integrity"]["queue_failure"] is True
