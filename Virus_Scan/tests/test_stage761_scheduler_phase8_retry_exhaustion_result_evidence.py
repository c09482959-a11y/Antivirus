from __future__ import annotations

from collections import deque

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


def test_stage761_retry_exhaustion_worker_error_result_failure_is_explicit_evidence():
    job_records = {7: {"file": "sample.bin", "attempt": 1, "history": []}}
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
        lifecycle_recorder=lambda _request: None,
        worker_error_result=lambda path, error: (_ for _ in ()).throw(RuntimeError("result factory unavailable")),
        pid=123,
    )

    assert decision.retried is False
    assert decision.completed_delta == 1
    assert failed == {7}
    assert terminal == {7}
    result = results["sample.bin"]
    assert result["retry_exhaustion_result_failed"] is True
    evidence = result["retry_exhaustion_result_evidence"]
    assert evidence["stage"] == "inmemory_retry_exhaustion_result"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    integrity = result["scan_integrity"]
    assert integrity["retry_exhaustion_result_failed"] is True
    assert integrity["queue_failure"] is True
    assert integrity["allow_learning"] is False
