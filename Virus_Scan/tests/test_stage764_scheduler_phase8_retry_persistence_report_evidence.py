from __future__ import annotations

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def test_stage764_retry_integrity_persistence_report_failure_is_distinct_evidence():
    def worker_once(path, prev, use_signal_timeout):
        return path, {"ok": True, "scan_integrity": {}}

    def set_integrity(_path, _integrity):
        raise RuntimeError("integrity unavailable")

    def report_retry_log_failure(_error, _context):
        raise RuntimeError("retry report unavailable")

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=worker_once,
        retry_max=lambda _prev: 0,
        is_retryable_failure=lambda _value: False,
        clear_integrity=lambda _path: None,
        get_integrity=lambda _path: {},
        set_integrity=set_integrity,
        report_retry_log_failure=report_retry_log_failure,
    ))

    integrity = result["scan_integrity"]
    assert integrity["queue_retry_integrity_persistence_failed"] is True
    assert integrity["queue_retry_integrity_persistence_report_failed"] is True
    report_evidence = integrity["queue_retry_integrity_persistence_report_evidence"]
    assert report_evidence["stage"] == "queue_retry_integrity_persistence_report"
    assert report_evidence["error_source"] == "queue.retry_policy.report_retry_log_failure"
    assert report_evidence["final_json_must_record"] is True
    assert report_evidence["checkpoint_must_record"] is True
    assert report_evidence["replay_must_reproduce"] is True
    assert integrity["queue_failure"] is True
    assert integrity["allow_learning"] is False
