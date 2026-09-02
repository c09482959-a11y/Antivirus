from __future__ import annotations

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def test_stage768_non_mapping_worker_result_becomes_retry_schema_evidence():
    _file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        prev="raw",
        use_signal_timeout=False,
        worker_once=lambda path, _prev, _use_signal_timeout: (path, "not-a-result-mapping"),
        retry_max=lambda _prev: 0,
        is_retryable_failure=lambda _value: False,
        clear_integrity=lambda _path: None,
        get_integrity=lambda _path: {},
        set_integrity=lambda _path, _integrity: None,
        report_retry_log_failure=lambda _exc, _ctx: None,
    ))

    integrity = result["scan_integrity"]
    assert result["result"] == "not-a-result-mapping"
    assert integrity["file_failed"] is True
    assert integrity["queue_retry_policy_callback_failed"] is True
    schema_evidence = [
        item for item in integrity["file_retry_failures"]
        if item.get("stage") == "queue_retry_policy_callback" and item.get("callback_name") == "worker_result_schema"
    ]
    assert schema_evidence
    assert schema_evidence[0]["final_json_must_record"] is True
    assert schema_evidence[0]["checkpoint_must_record"] is True
    assert schema_evidence[0]["replay_must_reproduce"] is True
