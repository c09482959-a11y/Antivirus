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

class _RecordingRecovery:
    def __init__(self):
        self.history = []

    def replace_with_history_transition(self, job_id, rec, reason, pid=None, now=None, action="history", extra=None):
        self.history.append((job_id, reason, action, pid, extra))
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
        self.history.append((job_id, reason, "retry_or_fail", pid, None))

    def request_cancel_only(self, job_id, reason, pid=None):
        self.history.append((job_id, reason, "cancel_only", pid, None))


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


def test_stage760_queued_backlog_uses_transition_owned_count_without_callback_authority():
    recovery = _RecordingRecovery()
    job_records = {1: {"state": "queued", "attempt": 0, "timeout_budget": {"timeout_budget": 9.0}}}
    kwargs = _base_kwargs(recovery, job_records)

    result = enforce_inmemory_timeout_sweep(**kwargs)

    assert result.queued_waits == 0
    assert job_records[1]["queued_timeout_armed_at"] == 100.0
    assert not tuple(result.timeout_retry_evidence)

    full_kwargs = _base_kwargs(recovery, job_records)
    full_kwargs["state_index"].sync_record(2, {"state": "queued"}, due_at=0.0)
    full_kwargs["max_queued_unstarted"] = 2
    job_records[1]["queued_timeout_armed_at"] = 0.0
    full_kwargs["state_index"].sync_record(1, job_records[1], due_at=0.0)
    full_result = enforce_inmemory_timeout_sweep(**full_kwargs)
    assert full_result.queued_waits == 1

def test_stage760_start_wait_budget_failure_is_timeout_policy_evidence_and_default_budget_used():
    recovery = _RecordingRecovery()
    job_records = {
        1: {
            "state": "assigned",
            "pid": 44,
            "assigned_at": 1.0,
            "attempt": 2,
            "timeout_budget": {"timeout_budget": 15.0},
        }
    }
    kwargs = _base_kwargs(recovery, job_records, now=100.0)

    def _broken_start_budget(rec, default):
        raise RuntimeError("budget callback unavailable")

    kwargs["start_wait_budget"] = _broken_start_budget

    result = enforce_inmemory_timeout_sweep(**kwargs)

    assert result.assigned_waits == 1
    evidence = tuple(result.timeout_retry_evidence)
    policy_records = [item for item in evidence if item.get("reason") == "assigned_start_wait_budget_failed"]
    assert policy_records
    record = policy_records[0]
    assert record["action"] == "start_wait_budget_failed"
    assert record["error_source"] == "inmemory_timeout_sweep.start_wait_budget"
    assert record["final_json_must_record"] is True
    assert recovery.history and recovery.history[-1][1] == "assigned_start_wait_no_retry"


def test_stage760_stage_classifier_failure_is_timeout_policy_evidence_before_cancel():
    recovery = _RecordingRecovery()
    job_records = {
        1: {
            "state": "running",
            "pid": 44,
            "running_at": 90.0,
            "last_heartbeat": 99.0,
            "last_progress_time": 1.0,
            "attempt": 3,
            "stage": "queued_preparation",
            "timeout_budget": {"timeout_budget": 1000.0, "heartbeat_stale_budget": 500.0, "stall_budget": 5.0},
        }
    }
    kwargs = _base_kwargs(recovery, job_records, now=100.0)

    def _broken_stage_classifier(stage):
        raise RuntimeError("stage classifier unavailable")

    kwargs["stage_is_pre_execution"] = _broken_stage_classifier

    result = enforce_inmemory_timeout_sweep(**kwargs)

    assert result.progress_stalls == 1
    evidence = tuple(result.timeout_retry_evidence)
    classifier_records = [item for item in evidence if item.get("reason") == "stage_pre_execution_classification_failed"]
    cancel_records = [item for item in evidence if item.get("reason") == "queue_worker_progress_stalled"]
    assert classifier_records
    assert cancel_records
    record = classifier_records[0]
    assert record["action"] == "stage_pre_execution_classification_failed"
    assert record["error_source"] == "inmemory_timeout_sweep.stage_is_pre_execution"
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage760_wall_time_failure_is_timeout_reporting_evidence():
    recovery = _RecordingRecovery()
    job_records = {1: {"state": "queued", "attempt": 0}}
    kwargs = _base_kwargs(recovery, job_records)

    def _broken_wall_time():
        raise RuntimeError("clock unavailable")

    kwargs["wall_time"] = _broken_wall_time

    result = enforce_inmemory_timeout_sweep(**kwargs)

    assert result.evaluated == 0
    reporting = tuple(result.timeout_reporting_failures)
    records = [item for item in reporting if item.get("reason") == "wall_time_read_failed"]
    assert records
    record = records[0]
    assert record["job_id"] == "timeout_sweep"
    assert record["error_category"] == "RuntimeError"
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True
