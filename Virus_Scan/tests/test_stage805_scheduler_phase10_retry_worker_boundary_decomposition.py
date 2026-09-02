from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)
from Virus_Scan.scheduler.workers.inmemory_worker_job_heartbeat import annotate_thread_progress_heartbeat_failure


def test_stage805_retry_policy_callbacks_mixed_module_is_deleted_and_bounded_modules_are_used() -> None:
    queue_root = Path("Virus_Scan/scheduler/queue")
    policy_source = (queue_root / "retry_policy.py").read_text()

    assert not (queue_root / "retry_policy_callbacks.py").exists()
    assert "retry_policy_callback_safety" in policy_source
    assert "retry_integrity_access" in policy_source
    assert "retry_integrity_persistence" in policy_source
    assert "retry_log_publication" in policy_source
    assert "retry_policy_callbacks" not in policy_source


def test_stage805_retry_integrity_persistence_remains_explicit_evidence() -> None:
    reports = []

    def worker_once(path, prev, use_signal_timeout):
        return path, {"scan_integrity": {"base": True}}

    def set_integrity(path, integrity):
        raise OSError("cannot persist integrity")

    last_file, result = run_file_with_retry(RetryPolicyRequest(
        "sample.bin",
        None,
        False,
        worker_once=worker_once,
        retry_max=lambda prev: 0,
        is_retryable_failure=lambda result: False,
        clear_integrity=lambda path: None,
        get_integrity=lambda path: {},
        set_integrity=set_integrity,
        report_retry_log_failure=lambda exc, context: reports.append((type(exc).__name__, dict(context))),
    ))

    integrity = result["scan_integrity"]
    assert last_file == "sample.bin"
    assert result["queue_retry_integrity_persistence_failed"] is True
    assert result["queue_retry_integrity_persistence_evidence"]["stage"] == "queue_retry_integrity_persistence"
    assert integrity["queue_retry_integrity_persistence_failed"] is True
    assert integrity["queue_failure"] is True
    assert reports == [("OSError", {"file": "sample.bin", "attempt": 1, "stage": "queue_retry_integrity_persistence"})]


def test_stage805_worker_job_delegates_heartbeat_and_publication_boundaries() -> None:
    worker_root = Path("Virus_Scan/scheduler/workers")
    job_source = (worker_root / "inmemory_worker_job.py").read_text()

    assert "inmemory_worker_job_heartbeat" in job_source
    assert "inmemory_worker_job_publication" in job_source
    assert "def _annotate_thread_progress_heartbeat_failure" not in job_source
    assert "def _running_publication_evidence" not in job_source

    output = annotate_thread_progress_heartbeat_failure(
        {"scan_integrity": {}},
        {"stage": "worker_heartbeat", "reason": "failed"},
    )

    assert output["worker_thread_progress_heartbeat_failed"] is True
    assert output["scan_integrity"]["worker_thread_progress_heartbeat_failed"] is True
    assert output["scan_integrity"]["worker_thread_progress_heartbeat_evidence"]["stage"] == "worker_heartbeat"
