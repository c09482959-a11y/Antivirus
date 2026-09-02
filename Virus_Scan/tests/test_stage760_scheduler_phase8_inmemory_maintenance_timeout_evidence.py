from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from types import SimpleNamespace

from Virus_Scan.scheduler.orchestration.inmemory_parent_maintenance import (
    InMemoryMaintenanceRequest,
    run_inmemory_parent_maintenance,
)



def _state_index_for(job_records):
    index = InMemorySchedulerStateIndex()
    if type(job_records) is dict:
        for job_id, record in dict.items(job_records):
            if type(job_id) is int and type(record) is dict:
                index.sync_record(job_id, record, due_at=0.0)
    return index

class _Recovery:
    completed = 0

    def __init__(self):
        self.history = []

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
        self.history.append((job_id, reason, "retry_or_fail", pid))

    def request_cancel_only(self, job_id, reason, pid=None):
        self.history.append((job_id, reason, "cancel_only", pid))
        return True

    def record_lifecycle_request(self, *args, **kwargs):
        self.history.append(("lifecycle", args, kwargs))

    def replace_with_history_transition(self, job_id, rec, reason, pid=None, now=None, action="history", extra=None):
        self.history.append((job_id, reason, action, pid))
        updated = dict(rec)
        updated["history"] = tuple(updated.get("history") or ()) + (
            {"reason": reason, "pid": pid, "action": action, "extra": dict(extra or {})},
        )
        return updated


def _request(job_records, recovery, **overrides):
    base = dict(
        procs=[],
        active={1: {"pid": 44}},
        terminal=set(),
        retry_job=recovery.retry_or_fail,
        worker_metrics={},
        memory_policy=SimpleNamespace(rss_limit_mb=0.0),
        recovery=recovery,
        job_records=job_records,
        state_index=_state_index_for(job_records),
        worker_heartbeats={},
        heartbeat_table=None,
        heartbeat_flags=None,
        max_queued_unstarted=10,
        queued_start_timeout_sec=5.0,
        assigned_start_timeout_sec=5.0,
        heartbeat_stale_sec=5.0,
        progress_stale_sec=5.0,
        base_pf_timeout=10.0,
        cancel_grace_sec=2.0,
        start_wait_budget=lambda rec, default: default,
        stage_is_pre_execution=lambda stage: False,
        ewma_state={},
        now=100.0,
        last_log=100.0,
        progress_every=10,
        total_files=1,
        pending=[],
        last_progress_total=-1,
        logging_module=SimpleNamespace(info=lambda *args, **kwargs: None),
        time_time=lambda: 100.0,
        time_monotonic_ns=lambda: 1000000,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError, KeyError, AttributeError),
    )
    base.update(overrides)
    return InMemoryMaintenanceRequest(**base)


def test_stage760_parent_maintenance_returns_and_attaches_timeout_retry_evidence():
    recovery = _Recovery()
    job_records = {
        1: {
            "state": "assigned",
            "pid": 44,
            "assigned_at": 1.0,
            "attempt": 2,
            "timeout_budget": {"timeout_budget": 15.0},
        }
    }

    def _broken_start_budget(rec, default):
        raise RuntimeError("budget callback unavailable")

    result = run_inmemory_parent_maintenance(
        _request(job_records, recovery, start_wait_budget=_broken_start_budget)
    )

    evidence = tuple(result.timeout_retry_evidence)
    assert any(item.get("reason") == "assigned_start_wait_budget_failed" for item in evidence)
    attached = tuple(job_records[1].get("timeout_retry_evidence") or ())
    assert any(item.get("reason") == "assigned_start_wait_budget_failed" for item in attached)
    assert job_records[1]["timeout_retry_evidence_recorded"] is True
    assert any(
        item.get("timeout_retry_evidence", {}).get("final_json_must_record") is True
        for item in job_records[1].get("history", ())
    )


def test_stage760_parent_maintenance_returns_timeout_reporting_failure_from_sweep_clock_failure():
    recovery = _Recovery()
    job_records = {1: {"state": "queued", "attempt": 0}}

    def _broken_time():
        raise RuntimeError("clock unavailable")

    result = run_inmemory_parent_maintenance(
        _request(job_records, recovery, time_time=_broken_time)
    )

    reporting = tuple(result.timeout_reporting_failures)
    assert any(item.get("reason") == "wall_time_read_failed" for item in reporting)
    record = [item for item in reporting if item.get("reason") == "wall_time_read_failed"][0]
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True
