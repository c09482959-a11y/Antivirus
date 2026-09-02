from __future__ import annotations

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def test_stage766_worker_result_malformed_scan_integrity_records_retry_schema_evidence():
    stored = {}

    def worker_once(path, prev, use_signal_timeout):
        return path, {"ok": True, "scan_integrity": ["not", "a", "mapping"]}

    _, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        None,
        False,
        worker_once=worker_once,
        retry_max=lambda prev: 0,
        is_retryable_failure=lambda value: False,
        clear_integrity=lambda path: None,
        get_integrity=lambda path: {},
        set_integrity=lambda path, integrity: stored.setdefault(path, dict(integrity)),
        report_retry_log_failure=lambda exc, context: None,
    ))

    integrity = result["scan_integrity"]
    assert integrity["queue_retry_policy_callback_failed"] is True
    assert integrity["queue_failure"] is True
    evidence = tuple(integrity["file_retry_failures"])
    matching = [item for item in evidence if item.get("callback_name") == "result_scan_integrity_schema"]
    assert matching
    assert matching[0]["final_json_must_record"] is True
    assert matching[0]["checkpoint_must_record"] is True
    assert matching[0]["replay_must_reproduce"] is True
    assert stored["sample.bin"]["queue_retry_policy_callback_failed"] is True


def test_stage766_get_integrity_malformed_return_records_retry_schema_evidence():
    stored = {}

    def worker_once(path, prev, use_signal_timeout):
        return path, {"ok": True}

    _, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        None,
        False,
        worker_once=worker_once,
        retry_max=lambda prev: 0,
        is_retryable_failure=lambda value: False,
        clear_integrity=lambda path: None,
        get_integrity=lambda path: ["not", "a", "mapping"],
        set_integrity=lambda path, integrity: stored.setdefault(path, dict(integrity)),
        report_retry_log_failure=lambda exc, context: None,
    ))

    integrity = result["scan_integrity"]
    assert integrity["queue_retry_policy_callback_failed"] is True
    assert integrity["queue_failure"] is True
    evidence = tuple(integrity["file_retry_failures"])
    matching = [item for item in evidence if item.get("callback_name") == "get_integrity_schema"]
    assert matching
    assert matching[0]["final_json_must_record"] is True
    assert matching[0]["checkpoint_must_record"] is True
    assert matching[0]["replay_must_reproduce"] is True
    assert stored["sample.bin"]["queue_retry_policy_callback_failed"] is True
