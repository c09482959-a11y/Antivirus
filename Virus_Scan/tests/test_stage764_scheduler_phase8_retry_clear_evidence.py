from __future__ import annotations

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def test_stage764_retry_clear_failure_records_immutable_retry_evidence():
    reports = []
    calls = {"worker": 0}

    def worker_once(path, prev, use_signal_timeout):
        calls["worker"] += 1
        return path, {"error": "retryable", "scan_integrity": {}}

    def retry_max(_prev):
        return 1

    def is_retryable_failure(_value):
        return True

    def clear_integrity(_path):
        raise RuntimeError("clear denied")

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=worker_once,
        retry_max=retry_max,
        is_retryable_failure=is_retryable_failure,
        clear_integrity=clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=lambda _path, _integrity: None,
        report_retry_log_failure=lambda exc, extra: reports.append((str(exc), dict(extra))),
    ))

    assert calls["worker"] == 2
    integrity = result["scan_integrity"]
    assert integrity["file_retry_exhausted"] is True
    assert integrity["queue_retry_integrity_clear_failed"] is True
    assert integrity["queue_failure"] is True
    assert integrity["allow_learning"] is False
    failures = tuple(integrity["file_retry_failures"])
    clear_records = [record for record in failures if record["stage"] == "queue_retry_integrity_clear"]
    assert clear_records
    evidence = clear_records[0]
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    assert reports and reports[0][1]["attempt"] == 1
