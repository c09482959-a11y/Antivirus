from __future__ import annotations

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def _no_retry(_value):
    return False


def _set_integrity(_path, _integrity):
    return None


def _clear_integrity(_path):
    return None


def _report_retry_log_failure(_error, _context):
    return None


def test_stage762_retry_max_failure_records_callback_evidence_without_aborting():
    def retry_max(_prev):
        raise RuntimeError("retry max unavailable")

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, prev, timeout: (path, {"ok": True}),
        retry_max=retry_max,
        is_retryable_failure=_no_retry,
        clear_integrity=_clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=_set_integrity,
        report_retry_log_failure=_report_retry_log_failure,
    ))

    integrity = result["scan_integrity"]
    assert integrity["queue_retry_policy_callback_failed"] is True
    evidence = integrity["file_retry_failures"][0]
    assert evidence["stage"] == "queue_retry_policy_callback"
    assert evidence["callback_name"] == "retry_max"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True


def test_stage762_retry_classifier_failure_records_callback_evidence_without_clean_result():
    def classifier(_value):
        raise RuntimeError("classifier unavailable")

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, prev, timeout: (path, {"status": "maybe"}),
        retry_max=lambda _prev: 2,
        is_retryable_failure=classifier,
        clear_integrity=_clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=_set_integrity,
        report_retry_log_failure=_report_retry_log_failure,
    ))

    integrity = result["scan_integrity"]
    assert integrity["queue_retry_policy_callback_failed"] is True
    evidence = [item for item in integrity["file_retry_failures"] if item["callback_name"] == "is_retryable_failure"]
    assert evidence
    assert evidence[0]["final_json_must_record"] is True


def test_stage762_retry_integrity_read_failure_records_callback_evidence():
    def get_integrity(_path):
        raise RuntimeError("integrity unavailable")

    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        {},
        False,
        worker_once=lambda path, prev, timeout: (path, {"ok": True}),
        retry_max=lambda _prev: 0,
        is_retryable_failure=_no_retry,
        clear_integrity=_clear_integrity,
        get_integrity=get_integrity,
        set_integrity=_set_integrity,
        report_retry_log_failure=_report_retry_log_failure,
    ))

    integrity = result["scan_integrity"]
    assert integrity["queue_retry_policy_callback_failed"] is True
    assert integrity["queue_retry_policy_callback_evidence"]["callback_name"] == "get_integrity"
    evidence = [item for item in integrity["file_retry_failures"] if item["callback_name"] == "get_integrity"]
    assert evidence[0]["checkpoint_must_record"] is True
