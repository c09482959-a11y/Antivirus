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


def _ingester(**kwargs):
    return SimpleNamespace(observed=0, cancel_requested=0)


def _base_kwargs(job_records, now=100.0) -> dict[str, Any]:
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
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError, OverflowError),
    )


def test_stage766_malformed_job_record_emits_timeout_evidence_without_aborting_sweep():
    kwargs = _base_kwargs({1: "not-a-job-record"})
    state_index = InMemorySchedulerStateIndex()
    state_index.sync_record(1, {"state": "queued"}, due_at=0.0)
    kwargs["state_index"] = state_index

    result = enforce_inmemory_timeout_sweep(**kwargs)

    assert result.evaluated == 1
    evidence = tuple(result.timeout_retry_evidence)
    assert len(evidence) == 1
    item = evidence[0]
    assert item["reason"] == "job_record_malformed"
    assert item["action"] == "timeout_job_record_malformed"
    assert item["final_json_must_record"] is True
    assert item["checkpoint_must_record"] is True
    assert item["replay_must_reproduce"] is True


def test_stage766_malformed_timeout_budget_container_emits_timeout_evidence_without_aborting_sweep():
    job_records = {
        1: {
            "state": "running",
            "pid": 44,
            "running_at": 1.0,
            "last_heartbeat": 99.0,
            "last_progress_time": 99.0,
            "attempt": 3,
            "stage": "raw_scan",
            "timeout_budget": ["not", "a", "mapping"],
        }
    }

    result = enforce_inmemory_timeout_sweep(**_base_kwargs(job_records))

    evidence = tuple(result.timeout_retry_evidence)
    malformed = [item for item in evidence if item.get("reason") == "timeout_budget_container_malformed"]
    assert malformed
    item = malformed[0]
    assert item["action"] == "timeout_budget_container_malformed"
    assert item["final_json_must_record"] is True
    assert item["checkpoint_must_record"] is True
    assert item["replay_must_reproduce"] is True
