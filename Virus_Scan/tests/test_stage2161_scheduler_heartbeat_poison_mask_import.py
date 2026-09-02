"""Stage2161 scheduler heartbeat poison-mask undefined-name closure."""
from __future__ import annotations

from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import InMemoryHeartbeatFlags
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_message import ingest_worker_heartbeat_message


def test_stage2161_poisoned_heartbeat_uses_no_hook_flag_boundary_without_name_error() -> None:
    job_records = {1: {"attempt": 0, "state": "running"}}
    active = {1: {}}
    worker_heartbeats: dict[int, float] = {}
    worker_metrics: dict[int, dict[str, object]] = {}
    cancellations: list[tuple[int, str, int | None]] = []

    applied = ingest_worker_heartbeat_message(
        message=("heartbeat", 1, "sample.bin", 77, 1.0, 0, 1, "scan", 10, 9, 4),
        job_records=job_records,
        active=active,
        terminal=set(),
        worker_heartbeats=worker_heartbeats,
        worker_metrics=worker_metrics,
        heartbeat_flags=InMemoryHeartbeatFlags(
            running=1,
            cancel_request=2,
            poisoned=4,
            stalled=8,
            force_retire=16,
        ),
        history_transition=lambda _job_id, record, _reason, **_kwargs: record,
        cancel_job=lambda job_id, reason, *, pid: cancellations.append((job_id, reason, pid)),
        lifecycle_recorder=lambda _request: None,
        wall_time=lambda: 2.0,
    )

    assert applied is True
    assert worker_heartbeats == {77: 1.0}
    assert worker_metrics[77]["flags"] == 4
    assert job_records[1]["last_heartbeat"] == 1.0
    assert cancellations == [(1, "worker_memory_toxic", 77)]
