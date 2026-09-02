from collections import deque

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


class RejectingResults(dict):
    def __setitem__(self, key, value):
        raise RuntimeError("result table unavailable")


def test_retry_exhaustion_result_publication_failure_records_queue_evidence():
    job_records = {7: {"file": "sample.bin", "attempt": 1, "history": ()}}
    active = {7: object()}
    pending = deque()
    results = RejectingResults()
    failed = set()
    terminal = set()

    decision = retry_or_fail(
        job_records=job_records,
        active=active,
        pending=pending,
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=7,
        reason="worker_timeout",
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=lambda path, error: {
            "file": str(path),
            "error": str(error),
            "scan_integrity": {"file_failed": True},
        },
        pid=31337,
    )

    assert decision.retried is False
    assert decision.completed_delta == 1
    assert 7 in failed
    assert 7 in terminal
    assert decision.evidence
    evidence = decision.evidence[0]
    assert evidence["stage"] == "inmemory_retry_result_publication"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    record = job_records[7]
    assert record["retry_result_publication_failed"] is True
    assert record["retry_result_publication_evidence"]["stage"] == "inmemory_retry_result_publication"
    assert record["state"] == "failed"
