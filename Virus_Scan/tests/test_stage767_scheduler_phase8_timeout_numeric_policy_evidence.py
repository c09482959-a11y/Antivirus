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

class _Recovery:
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
        return None

    def request_cancel_only(self, job_id, reason, pid=None):
        return True


def _base_kwargs(job_records, now=100.0, heartbeat_ingester=None) -> dict[str, Any]:
    suppressed = []
    recovery = _Recovery()
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
        heartbeat_ingester=heartbeat_ingester or (lambda **kwargs: SimpleNamespace(observed=0, cancel_requested=0)),
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
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError, OverflowError),
    )


def test_stage767_malformed_shared_heartbeat_counts_emit_timeout_reporting_evidence():
    result = enforce_inmemory_timeout_sweep(
        **_base_kwargs(
            {},
            heartbeat_ingester=lambda **kwargs: SimpleNamespace(observed="not-an-int", cancel_requested=object()),
        )
    )

    assert result.shared_heartbeats_observed == 0
    assert result.shared_heartbeat_cancel_requests == 0
    reasons = {item["reason"] for item in result.timeout_reporting_failures}
    assert "shared_heartbeats_observed_malformed" in reasons
    assert "shared_heartbeat_cancel_requests_malformed" in reasons
    for item in result.timeout_reporting_failures:
        assert item["final_json_must_record"] is True
        assert item["checkpoint_must_record"] is True
        assert item["replay_must_reproduce"] is True


def test_stage767_malformed_base_timeout_policy_values_emit_timeout_retry_evidence():
    job_records = {
        1: {
            "state": "running",
            "pid": 44,
            "running_at": 1.0,
            "last_heartbeat": 99.0,
            "last_progress_time": 99.0,
            "attempt": 2,
            "stage": "raw_scan",
            "timeout_budget": {},
        }
    }
    kwargs = _base_kwargs(job_records, now=100.0)
    kwargs.update(
        heartbeat_stale_sec="bad-heartbeat-budget",
        progress_stale_sec=float("inf"),
        base_pf_timeout="bad-hard-timeout",
    )

    result = enforce_inmemory_timeout_sweep(**kwargs)

    reasons = {item["reason"] for item in result.timeout_retry_evidence}
    assert "heartbeat_stale_sec_malformed" in reasons
    assert "progress_stale_sec_malformed" in reasons
    assert "base_pf_timeout_malformed" in reasons
    for item in result.timeout_retry_evidence:
        if item["reason"].endswith("_malformed"):
            assert item["final_json_must_record"] is True
            assert item["checkpoint_must_record"] is True
            assert item["replay_must_reproduce"] is True


def test_stage767_malformed_cancel_grace_policy_emits_evidence_before_kill_after_stall():
    job_records = {
        1: {
            "state": "running",
            "pid": 44,
            "running_at": 99.0,
            "last_heartbeat": 99.0,
            "last_progress_time": 1.0,
            "cancel_requested_at": 10.0,
            "attempt": 5,
            "stage": "raw_scan",
            "timeout_budget": {"stall_budget": 1.0},
        }
    }
    kwargs = _base_kwargs(job_records, now=100.0)
    kwargs["cancel_grace_sec"] = "bad-cancel-grace"

    result = enforce_inmemory_timeout_sweep(**kwargs)

    reasons = {item["reason"] for item in result.timeout_retry_evidence}
    assert "cancel_grace_sec_malformed" in reasons
    assert "queue_worker_killed_after_stall" in reasons
