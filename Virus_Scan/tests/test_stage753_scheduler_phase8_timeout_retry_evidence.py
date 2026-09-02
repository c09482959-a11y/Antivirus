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
    def __init__(self):
        self.transitions = []
        self.retries = []
        self.cancels = []

    def replace_with_history_transition(self, job_id, rec, reason, pid=None, now=None, action="history", extra=None):
        updated = dict(rec)
        updated["history"] = tuple(updated.get("history") or ()) + (
            {"reason": reason, "pid": pid, "action": action, "extra": dict(extra or {})},
        )
        self.transitions.append((job_id, reason, pid, action))
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
        self.retries.append((job_id, reason, pid))
        return None

    def request_cancel_only(self, job_id, reason, pid=None):
        self.cancels.append((job_id, reason, pid))
        return True


def _ingester(**kwargs):
    return SimpleNamespace(observed=0, cancel_requested=0)


def _base_kwargs(recovery, job_records, now=100.0) -> dict[str, Any]:
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
        record_scheduler_suppressed=lambda *args, **kwargs: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
    )


def test_stage753_hard_timeout_retry_emits_immutable_timeout_retry_evidence():
    recovery = _Recovery()
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
    assert recovery.retries == [(1, "queue_worker_hard_timeout", 44)]
    evidence = tuple(result.timeout_retry_evidence)
    assert evidence
    assert evidence[0]["stage"] == "inmemory_timeout_retry_escalation"
    assert evidence[0]["reason"] == "queue_worker_hard_timeout"
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["checkpoint_must_record"] is True
    assert evidence[0]["replay_must_reproduce"] is True


def test_stage753_progress_stall_cancel_emits_timeout_evidence_and_reporting_failure():
    recovery = _Recovery()
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

    def _bad_update(*args, **kwargs):
        raise RuntimeError("ewma write failed")

    def _bad_suppressed(*args, **kwargs):
        raise RuntimeError("suppression write failed")

    kwargs = _base_kwargs(recovery, job_records)
    kwargs["update_ewma"] = _bad_update
    kwargs["record_scheduler_suppressed"] = _bad_suppressed
    result = enforce_inmemory_timeout_sweep(**kwargs)

    assert result.progress_stalls == 1
    assert recovery.cancels == [(1, "queue_worker_progress_stalled", 44)]
    evidence = tuple(result.timeout_retry_evidence)
    reporting = tuple(result.timeout_reporting_failures)
    assert evidence[0]["reason"] == "queue_worker_progress_stalled"
    assert evidence[0]["action"] == "cancel_only"
    assert reporting[0]["stage"] == "inmemory_timeout_reporting"
    assert reporting[0]["replay_must_reproduce"] is True
