from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from typing import Any
from types import SimpleNamespace

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import enforce_inmemory_timeout_sweep



def _state_index_for(job_records):
    index = InMemorySchedulerStateIndex()
    if type(job_records) is dict:
        for job_id, record in dict.items(job_records):
            if type(job_id) is int and type(record) is dict:
                index.sync_record(job_id, record, due_at=0.0)
    return index

class _FailingRetryRecovery:
    def __init__(self):
        self.suppressed = []

    def replace_with_history_transition(self, job_id, rec, reason, pid=None, now=None, action="history", extra=None):
        updated = dict(rec)
        updated["history"] = tuple(updated.get("history") or ()) + (
            {"reason": reason, "pid": pid, "action": action, "extra": dict(extra or {})},
        )
        return updated

    def retry_evidence_count(self):
        return 0

    def retry_evidence_since(self, cursor):
        assert cursor == 0
        return ()

    def cancel_evidence_count(self):
        return 0

    def cancel_evidence_since(self, cursor):
        assert cursor == 0
        return ()

    def retry_or_fail(self, job_id, reason, pid=None):
        raise RuntimeError("retry escalation write denied")

    def request_cancel_only(self, job_id, reason, pid=None):
        raise RuntimeError("cancel escalation write denied")


def _ingester(**kwargs):
    return SimpleNamespace(observed=0, cancel_requested=0)


def _base_kwargs(recovery, job_records, now=100.0) -> dict[str, Any]:
    suppressed = []
    return dict(
        state_index=_state_index_for(job_records),
        job_records=job_records,
        active={1: {"pid": 44}},
        terminal=set(),
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_table=None,
        heartbeat_flags=None,
        read_heartbeat=lambda **kwargs: None,
        cancel_job=recovery.request_cancel_only,
        lifecycle_recorder=lambda _request: None,
        heartbeat_ingester=_ingester,
        monotonic_ns=lambda: 1000000,
        wall_time=lambda: now,
        recovery=recovery,
        max_queued_unstarted=10,
        queued_start_timeout_sec=5.0,
        assigned_start_timeout_sec=5.0,
        heartbeat_stale_sec=5.0,
        progress_stale_sec=5.0,
        base_pf_timeout=10.0,
        cancel_grace_sec=2.0,
        start_wait_budget=lambda rec, default: default,
        stage_is_pre_execution=lambda stage: False,
        update_ewma=lambda *args, **kwargs: None,
        ewma_state={},
        record_scheduler_suppressed=lambda name, exc: suppressed.append((name, type(exc).__name__, str(exc))),
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
    )


def test_stage754_hard_timeout_retry_failure_is_replay_visible_evidence():
    recovery = _FailingRetryRecovery()
    job_records = {
        1: {
            "state": "running",
            "pid": 44,
            "running_at": 1.0,
            "last_heartbeat": 95.0,
            "last_progress_time": 95.0,
            "attempt": 2,
            "timeout_budget": {"timeout_budget": 10.0, "heartbeat_stale_budget": 5.0, "stall_budget": 5.0},
        }
    }

    result = enforce_inmemory_timeout_sweep(**_base_kwargs(recovery, job_records))

    assert result.hard_timeouts == 1
    evidence = tuple(result.timeout_retry_evidence)
    failure_records = [item for item in evidence if item.get("action") == "retry_or_fail_failed"]
    assert failure_records
    record = failure_records[0]
    assert record["reason"] == "queue_worker_hard_timeout"
    assert record["error_category"] == "RuntimeError"
    assert record["error_source"] == "inmemory_timeout_sweep.retry_or_fail"
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage754_progress_stall_cancel_failure_is_replay_visible_evidence():
    recovery = _FailingRetryRecovery()
    job_records = {
        1: {
            "state": "running",
            "pid": 44,
            "running_at": 90.0,
            "last_heartbeat": 99.0,
            "last_progress_time": 1.0,
            "attempt": 1,
            "stage": "raw_scan",
            "timeout_budget": {"timeout_budget": 1000.0, "heartbeat_stale_budget": 500.0, "stall_budget": 5.0},
        }
    }

    result = enforce_inmemory_timeout_sweep(**_base_kwargs(recovery, job_records))

    assert result.progress_stalls == 1
    evidence = tuple(result.timeout_retry_evidence)
    failure_records = [item for item in evidence if item.get("action") == "cancel_only_failed"]
    assert failure_records
    record = failure_records[0]
    assert record["reason"] == "queue_worker_progress_stalled"
    assert record["error_source"] == "inmemory_timeout_sweep.request_cancel_only"
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage754_shared_heartbeat_ingest_failure_is_timeout_reporting_evidence():
    recovery = _FailingRetryRecovery()
    job_records = {
        1: {
            "state": "queued",
            "attempt": 0,
        }
    }

    def _bad_ingester(**kwargs):
        raise RuntimeError("shared heartbeat read failed")

    kwargs = _base_kwargs(recovery, job_records)
    kwargs["heartbeat_ingester"] = _bad_ingester
    result = enforce_inmemory_timeout_sweep(**kwargs)

    assert result.shared_heartbeats_observed == 0
    reporting = tuple(result.timeout_reporting_failures)
    assert reporting
    record = reporting[0]
    assert record["stage"] == "inmemory_timeout_reporting"
    assert record["job_id"] == "shared_heartbeat"
    assert record["reason"] == "shared_heartbeat_ingest_failed"
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True
