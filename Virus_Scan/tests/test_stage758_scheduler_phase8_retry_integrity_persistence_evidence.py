from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)


def test_stage758_retry_success_integrity_persistence_failure_is_explicit_evidence():
    reports = []

    def worker_once(path, prev, use_signal_timeout):
        return path, {"ok": True, "scan_integrity": {}}

    def failing_set_integrity(path, integrity):
        raise RuntimeError("integrity store unavailable")

    file_path, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        "unknown",
        True,
        worker_once=worker_once,
        retry_max=lambda stage: 0,
        is_retryable_failure=lambda value: False,
        clear_integrity=lambda path: None,
        get_integrity=lambda path: {},
        set_integrity=failing_set_integrity,
        report_retry_log_failure=lambda exc, extra: reports.append((str(exc), dict(extra))),
    ))

    assert file_path == "sample.bin"
    assert result["queue_retry_integrity_persistence_failed"] is True
    integrity = result["scan_integrity"]
    assert integrity["queue_retry_integrity_persistence_failed"] is True
    assert integrity["queue_failure"] is True
    assert integrity["allow_learning"] is False
    evidence = integrity["queue_retry_integrity_persistence_evidence"]
    assert evidence["stage"] == "queue_retry_integrity_persistence"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    assert reports and reports[0][1]["stage"] == "queue_retry_integrity_persistence"


def test_stage758_retry_exhaustion_integrity_persistence_failure_preserves_exhaustion_evidence():
    def worker_once(path, prev, use_signal_timeout):
        return path, {"error": "transient", "scan_integrity": {}}

    file_path, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        "unknown",
        True,
        worker_once=worker_once,
        retry_max=lambda stage: 1,
        is_retryable_failure=lambda value: True,
        clear_integrity=lambda path: None,
        get_integrity=lambda path: {},
        set_integrity=lambda path, integrity: (_ for _ in ()).throw(RuntimeError("write denied")),
        report_retry_log_failure=lambda exc, extra: None,
    ))

    assert file_path == "sample.bin"
    integrity = result["scan_integrity"]
    assert integrity["file_retry_exhausted"] is True
    assert integrity["file_failed"] is True
    assert integrity["queue_retry_integrity_persistence_failed"] is True
    assert tuple(integrity["queue_retry_integrity_persistence_failures"])


def test_stage758_duplicate_execution_retry_path_removed_after_call_site_proof():
    duplicate_path = Path(__file__).parents[1] / "scheduler" / "execution" / "retry_engine.py"
    assert not duplicate_path.exists()
