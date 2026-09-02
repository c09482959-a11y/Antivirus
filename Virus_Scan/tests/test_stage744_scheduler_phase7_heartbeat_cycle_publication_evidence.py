from __future__ import annotations

from dataclasses import FrozenInstanceError

from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle import (
    InMemoryWorkerHeartbeatCycleResult,
    publish_inmemory_worker_heartbeat_cycle,
)


class Flags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def test_heartbeat_cycle_reports_failed_publication_in_immutable_result():
    meta = {"job_id": 11, "attempt": 4, "stage": "scan", "progress_counter": 2}
    reports: list[tuple[str, str]] = []

    result = publish_inmemory_worker_heartbeat_cycle(
        active={object(): meta},
        cfg={},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        cancel_requested=lambda *_args, **_kwargs: False,
        update_shared_heartbeat=lambda *_args, **_kwargs: False,
        process_id=1234,
        now_hb=50.0,
        last_heartbeat_emit=10.0,
        heartbeat_interval=1.0,
        heartbeat_seq=8,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda label, exc: reports.append((label, str(exc))),
    )

    assert isinstance(result, InMemoryWorkerHeartbeatCycleResult)
    assert result.heartbeat_published is False
    assert result.heartbeat_failure_count == 1
    assert result.heartbeat_failure_evidence[0]["worker_heartbeat_publish_failed"] is True
    assert result.heartbeat_failure_evidence[0]["worker_heartbeat_job_id"] == "11"
    assert meta["heartbeat_publish_failed"] is True
    assert "last_hb" not in meta
    assert reports and reports[0][0] == "worker_heartbeat_publish_failed"

    try:
        result.heartbeat_failure_count = 0
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("heartbeat cycle evidence must remain immutable")
