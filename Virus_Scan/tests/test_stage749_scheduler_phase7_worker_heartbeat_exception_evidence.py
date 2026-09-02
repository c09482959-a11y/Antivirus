from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle import publish_inmemory_worker_heartbeat_cycle
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_publisher import publish_active_worker_heartbeats


class Flags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def test_stage749_active_worker_heartbeat_exception_becomes_evidence():
    meta = {"job_id": 12, "attempt": 4, "stage": "scan", "progress_counter": 1}
    reports = []

    publish_active_worker_heartbeats(
        active_items=((object(), meta),),
        cfg={},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        cancel_requested=lambda *_a, **_k: False,
        update_shared_heartbeat=lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("writer exploded")),
        process_id=321,
        now_hb=10.0,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda label, exc: reports.append((label, str(exc))),
    )

    assert meta["heartbeat_publish_failed"] is True
    evidence = meta["heartbeat_publish_evidence"]
    assert evidence["worker_heartbeat_publish_failed"] is True
    assert evidence["worker_heartbeat_job_id"] == "12"
    assert evidence["worker_heartbeat_attempt"] == 4
    assert "RuntimeError" in evidence["worker_heartbeat_failure_reason"]
    assert reports and reports[0][0] == "worker_heartbeat_publish_failed"


def test_stage749_heartbeat_cycle_reports_exception_publication_failure():
    future = object()
    active = {future: {"job_id": 13, "attempt": 1, "stage": "scan", "progress_counter": 2}}

    result = publish_inmemory_worker_heartbeat_cycle(
        active=active,
        cfg={},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        cancel_requested=lambda *_a, **_k: False,
        update_shared_heartbeat=lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("writer exploded")),
        process_id=1,
        now_hb=100.0,
        last_heartbeat_emit=0.0,
        heartbeat_interval=0.0,
        heartbeat_seq=0,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda *_a, **_k: None,
    )

    assert result.heartbeat_published is False
    assert result.heartbeat_failure_count == 1
    assert result.heartbeat_failure_evidence[0]["worker_heartbeat_job_id"] == "13"
