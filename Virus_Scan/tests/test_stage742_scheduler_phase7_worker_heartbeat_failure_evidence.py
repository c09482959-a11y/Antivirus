from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_publisher import (
    WorkerHeartbeatPublishEvidence,
    publish_active_worker_heartbeats,
)


class Flags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def test_worker_heartbeat_publish_failure_is_evidence_backed_and_not_marked_fresh():
    meta = {
        "job_id": 7,
        "attempt": 3,
        "stage": "scan",
        "progress_counter": 4,
    }
    reports: list[tuple[str, str]] = []

    stopped = publish_active_worker_heartbeats(
        active_items=((object(), meta),),
        cfg={},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        cancel_requested=lambda *_args, **_kwargs: False,
        update_shared_heartbeat=lambda *_args, **_kwargs: False,
        process_id=123,
        now_hb=456.0,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda label, exc: reports.append((label, str(exc))),
    )

    assert stopped is False
    assert "last_hb" not in meta
    assert meta["heartbeat_publish_failed"] is True
    evidence = meta["heartbeat_publish_evidence"]
    assert evidence["worker_heartbeat_publish_failed"] is True
    assert evidence["worker_heartbeat_job_id"] == "7"
    assert evidence["worker_heartbeat_attempt"] == 3
    assert evidence["worker_heartbeat_stage"] == "scan"
    assert reports and reports[0][0] == "worker_heartbeat_publish_failed"


def test_worker_heartbeat_publish_evidence_is_immutable_metadata_contract():
    evidence = WorkerHeartbeatPublishEvidence(
        job_id="9",
        attempt=2,
        stage="raw",
        reason="unit failure",
    )

    metadata = evidence.as_metadata()
    assert metadata["worker_heartbeat_publish_failed"] is True
    assert metadata["worker_heartbeat_job_id"] == "9"
    assert metadata["worker_heartbeat_attempt"] == 2
    assert metadata["worker_heartbeat_stage"] == "raw"
    assert metadata["worker_heartbeat_failure_reason"] == "unit failure"
