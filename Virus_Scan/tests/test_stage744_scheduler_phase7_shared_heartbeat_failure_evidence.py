from __future__ import annotations

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.workers.heartbeat import (
    WorkerSharedHeartbeatFailureEvidence,
    cooperative_cancel_requested,
    read_shared_heartbeat,
    update_shared_heartbeat,
)


class RaisingLookup(dict):
    def get(self, *_args, **_kwargs):
        raise RuntimeError("shared table read failed")


class RaisingSlot:
    def __len__(self):
        return 1

    def __getitem__(self, _idx):
        return 0

    def __setitem__(self, _idx, _value):
        raise RuntimeError("shared table write failed")


def test_shared_heartbeat_cancel_read_failure_records_scheduler_evidence():
    clear_failure_records()

    assert cooperative_cancel_requested(RaisingLookup(), 5, 1) is False

    snapshot = failure_snapshot()
    assert any("worker_shared_heartbeat_cancel_read_failed" in str(key) for key in snapshot["records"])


def test_shared_heartbeat_read_failure_records_scheduler_evidence():
    clear_failure_records()

    assert read_shared_heartbeat(RaisingLookup(), 5, 1) is None

    snapshot = failure_snapshot()
    assert any("worker_shared_heartbeat_heartbeat_read_failed" in str(key) for key in snapshot["records"])


def test_shared_heartbeat_write_failure_records_scheduler_evidence():
    clear_failure_records()
    table = {
        "generation": RaisingSlot(),
        "monotonic_ns": RaisingSlot(),
        "pid": RaisingSlot(),
        "thread_id": RaisingSlot(),
        "stage": RaisingSlot(),
        "progress_counter": RaisingSlot(),
        "bytes_processed": RaisingSlot(),
        "last_progress_ns": RaisingSlot(),
        "flags": RaisingSlot(),
        "rss_mb": RaisingSlot(),
        "completed_jobs": RaisingSlot(),
    }

    assert update_shared_heartbeat(table, 0, 2) is False

    snapshot = failure_snapshot()
    assert any("worker_shared_heartbeat_heartbeat_write_failed" in str(key) for key in snapshot["records"])


def test_shared_heartbeat_failure_evidence_context_is_immutable_metadata():
    evidence = WorkerSharedHeartbeatFailureEvidence(
        operation="heartbeat_write",
        job_id="3",
        generation=7,
        reason="RuntimeError: unit failure",
    )

    context = evidence.as_context()
    assert context["worker_shared_heartbeat_failed"] is True
    assert context["worker_shared_heartbeat_operation"] == "heartbeat_write"
    assert context["worker_shared_heartbeat_job_id"] == "3"
    assert context["worker_shared_heartbeat_generation"] == 7
