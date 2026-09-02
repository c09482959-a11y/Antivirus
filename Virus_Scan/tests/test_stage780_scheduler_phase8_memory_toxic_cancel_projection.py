from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import InMemoryRecoveryEvidenceJournal

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

    def __init__(self) -> None:
        self.evidence_journal = InMemoryRecoveryEvidenceJournal()
        self.history = []

    def retry_or_fail(self, job_id, reason, pid=None):
        self.history.append((job_id, reason, "retry_or_fail", pid))
        return False

    def request_cancel_only(self, job_id, reason, pid=None):
        evidence = {
            "stage": "inmemory_retry_cancel_publication",
            "job_id": job_id,
            "generation": 0,
            "reason": reason,
            "flags": 0,
            "error_category": "RuntimeError",
            "error_source": "memory_toxicity_cancel_publication",
            "detail": "cancel publication degraded during memory-toxicity escalation",
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_reproduce": True,
        }
        self.evidence_journal.append_cancel((evidence,))
        self.history.append((job_id, reason, "cancel_only", pid))
        return True

    def retry_evidence_count(self):
        return self.evidence_journal.retry_count()

    def retry_evidence_since(self, cursor):
        return self.evidence_journal.retry_since(cursor)

    def cancel_evidence_count(self):
        return self.evidence_journal.cancel_count()

    def cancel_evidence_since(self, cursor):
        return self.evidence_journal.cancel_since(cursor)

    def record_lifecycle_request(self, *args, **kwargs):
        self.history.append(("lifecycle", args, kwargs))

    def append_empty_drain_evidence(self, records):
        return self.evidence_journal.append_empty_drain(records)

    def replace_with_history_transition(self, job_id, rec, reason, pid=None, now=None, action="history", extra=None):
        updated = dict(rec)
        updated["history"] = tuple(updated.get("history") or ()) + (
            {"reason": reason, "pid": pid, "action": action, "extra": dict(extra or {})},
        )
        return updated


def _request(job_records, recovery, worker_metrics, **overrides):
    base = dict(
        procs=[],
        active={1: {"pid": 44, "state": "running"}},
        terminal=set(),
        retry_job=recovery.retry_or_fail,
        worker_metrics=worker_metrics,
        memory_policy=SimpleNamespace(rss_limit_mb=128.0),
        recovery=recovery,
        job_records=job_records,
        state_index=_state_index_for(job_records),
        worker_heartbeats={},
        heartbeat_table=None,
        heartbeat_flags=None,
        max_queued_unstarted=10,
        queued_start_timeout_sec=5000.0,
        assigned_start_timeout_sec=5000.0,
        heartbeat_stale_sec=5000.0,
        progress_stale_sec=5000.0,
        base_pf_timeout=5000.0,
        cancel_grace_sec=5000.0,
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


def test_stage780_parent_maintenance_projects_memory_toxic_cancel_evidence():
    recovery = _Recovery()
    job_records = {
        1: {
            "state": "assigned",
            "pid": 44,
            "assigned_at": 99.0,
            "attempt": 0,
            "timeout_budget": {"timeout_budget": 5000.0, "stall_budget": 5000.0},
        }
    }
    worker_metrics = {44: {"rss_mb": 512.0}}

    result = run_inmemory_parent_maintenance(
        _request(job_records, recovery, worker_metrics)
    )

    evidence = tuple(result.timeout_retry_evidence)
    assert any(
        item.get("stage") == "inmemory_retry_cancel_publication"
        and item.get("reason") == "worker_memory_toxic"
        for item in evidence
    )
    attached = tuple(job_records[1].get("timeout_retry_evidence") or ())
    assert any(item.get("reason") == "worker_memory_toxic" for item in attached)
    assert job_records[1]["timeout_retry_evidence_recorded"] is True
