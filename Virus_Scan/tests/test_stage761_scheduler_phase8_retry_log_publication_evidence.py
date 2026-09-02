from __future__ import annotations

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def test_stage761_retry_clear_log_failure_is_evidence_not_abort():
    calls = []

    def worker_once(path, prev, use_signal_timeout):
        calls.append(path)
        return path, {"error": "transient", "scan_integrity": {}}

    def clear_integrity(path):
        raise RuntimeError("clear denied")

    def report_retry_log_failure(exc, extra):
        raise RuntimeError("retry log unavailable")

    file_path, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        "unknown",
        True,
        worker_once=worker_once,
        retry_max=lambda stage: 1,
        is_retryable_failure=lambda value: bool(value and value.get("error")),
        clear_integrity=clear_integrity,
        get_integrity=lambda path: {},
        set_integrity=lambda path, integrity: None,
        report_retry_log_failure=report_retry_log_failure,
    ))

    assert file_path == "sample.bin"
    assert len(calls) == 2
    integrity = result["scan_integrity"]
    assert integrity["file_retry_integrity_clear_failed"] is True
    assert integrity["queue_retry_log_publication_failed"] is True
    assert integrity["queue_failure"] is True
    evidence = [item for item in integrity["file_retry_failures"] if item.get("stage") == "queue_retry_log_publication"]
    assert evidence
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["checkpoint_must_record"] is True
    assert evidence[0]["replay_must_reproduce"] is True
    assert "retry integrity clear failed" in evidence[0]["original_error"]
