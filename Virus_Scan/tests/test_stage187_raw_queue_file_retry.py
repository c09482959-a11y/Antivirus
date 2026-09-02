from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def test_run_file_with_retry_records_successful_retry_integrity():
    calls = []
    integrity = {}

    def worker_once(path, prev, use_signal_timeout):
        calls.append((path, prev, use_signal_timeout))
        if len(calls) == 1:
            return path, {"error": "transient", "scan_integrity": {"had_degraded_stage": True}}
        return path, {"ok": True, "scan_integrity": {}}

    def set_integrity(path, value):
        integrity[path] = dict(value)

    file_path, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        "unknown",
        True,
        worker_once=worker_once,
        retry_max=lambda stage: 1,
        is_retryable_failure=lambda result: bool(result and result.get("error") == "transient"),
        clear_integrity=lambda path: None,
        get_integrity=lambda path: {},
        set_integrity=set_integrity,
        report_retry_log_failure=lambda exc, extra: None,
    ))

    assert file_path == "sample.bin"
    assert result["file_retried"] is True
    assert result["scan_integrity"]["file_retried"] is True
    assert result["scan_integrity"]["file_retry_attempts"] == 2
    assert integrity["sample.bin"]["file_retry_attempts"] == 2


def test_run_file_with_retry_exhaustion_is_replay_visible():
    integrity = {}

    def worker_once(path, prev, use_signal_timeout):
        return path, {"error": "transient", "scan_integrity": {}}

    file_path, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        "unknown",
        True,
        worker_once=worker_once,
        retry_max=lambda stage: 1,
        is_retryable_failure=lambda result: True,
        clear_integrity=lambda path: None,
        get_integrity=lambda path: {},
        set_integrity=lambda path, value: integrity.setdefault(path, dict(value)),
        report_retry_log_failure=lambda exc, extra: None,
    ))

    assert file_path == "sample.bin"
    assert result["scan_integrity"]["file_failed"] is True
    assert result["scan_integrity"]["file_retry_exhausted"] is True
    assert result["scan_integrity"]["file_retry_attempts"] == 2
    assert integrity["sample.bin"]["file_retry_exhausted"] is True
