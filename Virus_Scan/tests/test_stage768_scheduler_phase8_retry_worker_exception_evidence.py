from __future__ import annotations

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def test_stage768_worker_once_exception_becomes_retry_callback_evidence():
    calls = {"worker": 0, "clear": 0}

    def worker_once(path, prev, use_signal_timeout):
        calls["worker"] += 1
        if calls["worker"] == 1:
            raise RuntimeError("scanner worker crashed before result")
        return path, {"ok": True, "scan_integrity": {}}

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        prev="raw",
        use_signal_timeout=False,
        worker_once=worker_once,
        retry_max=lambda _prev: 1,
        is_retryable_failure=lambda value: bool(isinstance(value, dict) and value.get("error")),
        clear_integrity=lambda _path: calls.__setitem__("clear", calls["clear"] + 1),
        get_integrity=lambda _path: {},
        set_integrity=lambda _path, _integrity: None,
        report_retry_log_failure=lambda _exc, _ctx: None,
    ))

    integrity = result["scan_integrity"]
    assert result["ok"] is True
    assert result["file_retried"] is True
    assert integrity["file_retried"] is True
    assert calls["worker"] == 2
    assert calls["clear"] == 1
    worker_evidence = [
        item for item in integrity["file_retry_failures"]
        if item.get("stage") == "queue_retry_policy_callback" and item.get("callback_name") == "worker_once"
    ]
    assert worker_evidence
    assert worker_evidence[0]["final_json_must_record"] is True
    assert worker_evidence[0]["checkpoint_must_record"] is True
    assert worker_evidence[0]["replay_must_reproduce"] is True


def test_stage768_worker_once_exception_exhaustion_remains_degraded():
    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        prev="raw",
        use_signal_timeout=False,
        worker_once=lambda _path, _prev, _use_signal_timeout: (_ for _ in ()).throw(RuntimeError("crash")),
        retry_max=lambda _prev: 0,
        is_retryable_failure=lambda value: bool(isinstance(value, dict) and value.get("error")),
        clear_integrity=lambda _path: None,
        get_integrity=lambda _path: {},
        set_integrity=lambda _path, _integrity: None,
        report_retry_log_failure=lambda _exc, _ctx: None,
    ))

    integrity = result["scan_integrity"]
    assert result["exception_type"] == "RuntimeError"
    assert integrity["file_failed"] is True
    assert integrity["file_retry_exhausted"] is True
    assert integrity["queue_retry_policy_callback_failed"] is True
    assert any(item.get("callback_name") == "worker_once" for item in integrity["file_retry_failures"])
