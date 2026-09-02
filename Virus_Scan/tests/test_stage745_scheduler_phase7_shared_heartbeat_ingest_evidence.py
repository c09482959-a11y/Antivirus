from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.workers.inmemory_shared_heartbeat import ingest_shared_heartbeats


@dataclass(frozen=True)
class Flags:
    poisoned_or_retire_mask: int = 4


def _base_kwargs(**overrides):
    values = {
        "active_job_ids": (1,),
        "job_records": {1: {"attempt": 2, "state": "running", "pid": 99}},
        "active": {1: {}},
        "terminal": set(),
        "worker_heartbeats": {},
        "worker_metrics": {},
        "heartbeat_table": object(),
        "heartbeat_flags": Flags(),
        "read_heartbeat": lambda *_args, **_kwargs: None,
        "cancel_job": lambda *_args, **_kwargs: None,
        "lifecycle_recorder": lambda *_args, **_kwargs: None,
        "monotonic_ns": lambda: 2_000_000_000,
        "wall_time": lambda: 10.0,
    }
    values.update(overrides)
    return values


def test_shared_heartbeat_ingest_read_failure_records_worker_evidence_and_continues():
    clear_failure_records()

    def read_failure(*_args, **_kwargs):
        raise RuntimeError("shared heartbeat read failed")

    result = ingest_shared_heartbeats(**_base_kwargs(read_heartbeat=read_failure))

    assert result.observed == 0
    assert result.heartbeat_read_failures == 1
    snapshot = failure_snapshot()
    assert any("worker_shared_heartbeat_heartbeat_ingest_read_failed" in str(key) for key in snapshot["records"])


def test_shared_heartbeat_ingest_malformed_row_records_worker_evidence_without_clean_observation():
    clear_failure_records()

    def malformed_row(*_args, **_kwargs):
        return {
            "monotonic_ns": "bad-monotonic",
            "pid": 99,
            "progress_counter": 3,
            "stage": "scan",
            "bytes_processed": 5,
            "last_progress_ns": 1,
            "flags": 0,
        }

    result = ingest_shared_heartbeats(**_base_kwargs(read_heartbeat=malformed_row))

    assert result.observed == 0
    assert result.heartbeat_row_failures == 1
    snapshot = failure_snapshot()
    assert any("worker_shared_heartbeat_heartbeat_ingest_row_failed" in str(key) for key in snapshot["records"])


def test_shared_heartbeat_ingest_lifecycle_failure_records_evidence_but_keeps_observation():
    clear_failure_records()

    def valid_row(*_args, **_kwargs):
        return {
            "monotonic_ns": 1_000_000_000,
            "pid": 99,
            "progress_counter": 3,
            "stage": "scan",
            "bytes_processed": 5,
            "last_progress_ns": 7,
            "flags": 0,
            "rss_mb": 12.5,
            "completed_jobs": 1,
        }

    def lifecycle_failure(*_args, **_kwargs):
        raise RuntimeError("lifecycle write failed")

    active = {1: {}}
    worker_heartbeats = {}
    worker_metrics = {}
    result = ingest_shared_heartbeats(
        **_base_kwargs(
            active=active,
            worker_heartbeats=worker_heartbeats,
            worker_metrics=worker_metrics,
            read_heartbeat=valid_row,
            lifecycle_recorder=lifecycle_failure,
        )
    )

    assert result.observed == 1
    assert result.lifecycle_record_failures == 1
    assert active[1]["heartbeat_seq"] == 3
    assert worker_heartbeats[99] == 9.0
    assert worker_metrics[99]["rss_mb"] == 12.5
    snapshot = failure_snapshot()
    assert any("worker_shared_heartbeat_heartbeat_ingest_lifecycle_failed" in str(key) for key in snapshot["records"])


def test_shared_heartbeat_ingest_cancel_failure_records_worker_evidence():
    clear_failure_records()

    def poison_row(*_args, **_kwargs):
        return {
            "monotonic_ns": 1_000_000_000,
            "pid": 99,
            "progress_counter": 3,
            "stage": "scan",
            "bytes_processed": 5,
            "last_progress_ns": 7,
            "flags": 4,
            "rss_mb": 12.5,
            "completed_jobs": 1,
        }

    def cancel_failure(*_args, **_kwargs):
        raise RuntimeError("cancel publish failed")

    result = ingest_shared_heartbeats(**_base_kwargs(read_heartbeat=poison_row, cancel_job=cancel_failure))

    assert result.observed == 1
    assert result.cancel_requested == 0
    assert result.cancel_request_failures == 1
    snapshot = failure_snapshot()
    assert any("worker_shared_heartbeat_heartbeat_ingest_cancel_failed" in str(key) for key in snapshot["records"])


def test_shared_heartbeat_uses_canonical_progress_signature_and_dedupes_unchanged_history():
    lifecycle: list[object] = []
    job_records = {
        1: {
            "attempt": 2,
            "state": "running",
            "pid": 99,
            "last_progress_signature": ("scan", 0, 0, 0),
            "last_progress_time": 1.0,
        }
    }
    active = {1: {}}
    worker_heartbeats = {}
    worker_metrics = {}

    row = {
        "monotonic_ns": 1_000_000_000,
        "pid": 99,
        "progress_counter": 0,
        "stage": "scan",
        "bytes_processed": 0,
        "last_progress_ns": 0,
        "flags": 0,
        "rss_mb": 12.5,
        "completed_jobs": 1,
    }

    for wall in (10.0, 11.0):
        result = ingest_shared_heartbeats(
            **_base_kwargs(
                job_records=job_records,
                active=active,
                worker_heartbeats=worker_heartbeats,
                worker_metrics=worker_metrics,
                read_heartbeat=lambda *_args, **_kwargs: row,
                lifecycle_recorder=lambda request: lifecycle.append(request),
                monotonic_ns=lambda: 2_000_000_000,
                wall_time=lambda wall=wall: wall,
            )
        )
        assert result.observed == 1

    assert lifecycle == []
    assert job_records[1]["last_progress_signature"] == ("scan", 0, 0, 0)
    assert job_records[1]["last_progress_time"] == 1.0
    assert worker_heartbeats[99] == 10.0
    assert worker_metrics[99]["last_seen"] == 10.0


def test_shared_heartbeat_progress_records_one_lifecycle_transition_with_canonical_signature():
    lifecycle: list[object] = []
    job_records = {
        1: {
            "attempt": 2,
            "state": "running",
            "pid": 99,
            "last_progress_signature": ("scan", 0, 0, 0),
        }
    }
    row = {
        "monotonic_ns": 1_000_000_000,
        "pid": 99,
        "progress_counter": 1,
        "stage": "scan",
        "bytes_processed": 4,
        "last_progress_ns": 9,
        "flags": 0,
        "rss_mb": 12.5,
        "completed_jobs": 1,
    }
    result = ingest_shared_heartbeats(
        **_base_kwargs(
            job_records=job_records,
            read_heartbeat=lambda *_args, **_kwargs: row,
            lifecycle_recorder=lambda request: lifecycle.append(request),
        )
    )
    assert result.observed == 1
    assert len(lifecycle) == 1
    assert lifecycle[0].transition == "shared_heartbeat"
    assert job_records[1]["last_progress_signature"] == ("scan", 1, 4, 9)
