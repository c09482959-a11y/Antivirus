from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import InMemoryRecoveryEvidenceJournal

from types import SimpleNamespace

from Virus_Scan.scheduler.orchestration.inmemory_parent_maintenance import (
    InMemoryMaintenanceRequest,
    run_inmemory_parent_maintenance,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import enforce_inmemory_timeout_sweep



def _state_index_for(job_records):
    index = InMemorySchedulerStateIndex()
    if type(job_records) is dict:
        for job_id, record in dict.items(job_records):
            if type(job_id) is int and type(record) is dict:
                index.sync_record(job_id, record, due_at=0.0)
    return index

class _RecoveryWithDecisionEvidence:
    completed = 0

    def __init__(self):
        self.transitions = []
        self.evidence_journal = InMemoryRecoveryEvidenceJournal()

    def replace_with_history_transition(self, job_id, rec, reason, pid=None, now=None, action="history", extra=None):
        updated = dict(rec)
        updated["history"] = tuple(updated.get("history") or ()) + (
            {"reason": reason, "pid": pid, "action": action, "extra": dict(extra or {})},
        )
        self.transitions.append((job_id, reason, pid, action))
        return updated

    def retry_or_fail(self, job_id, reason, pid=None):
        self.evidence_journal.append_retry((
            {
                "stage": "inmemory_retry_pending_publication",
                "job_id": job_id,
                "reason": reason,
                "pid": pid,
                "action": "retry_pending_publication_failed",
                "queue_failure": True,
                "retry_failure": True,
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_reproduce": True,
            },
        ))
        return False

    def retry_evidence_count(self):
        return self.evidence_journal.retry_count()

    def retry_evidence_since(self, cursor):
        return self.evidence_journal.retry_since(cursor)

    def cancel_evidence_count(self):
        return self.evidence_journal.cancel_count()

    def cancel_evidence_since(self, cursor):
        return self.evidence_journal.cancel_since(cursor)

    def request_cancel_only(self, job_id, reason, pid=None):
        return False

    def record_lifecycle_request(self, *_args, **_kwargs):
        return None

    def append_empty_drain_evidence(self, records):
        return self.evidence_journal.append_empty_drain(records)


def _job_records():
    return {
        1: {
            "state": "running",
            "pid": 44,
            "running_at": 1.0,
            "last_heartbeat": 99.0,
            "last_progress_time": 99.0,
            "attempt": 1,
            "timeout_budget": {"timeout_budget": 15.0, "heartbeat_stale_budget": 15.0, "stall_budget": 15.0},
            "history": (),
        }
    }


def _sweep_kwargs(recovery, job_records):
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
        lifecycle_recorder=recovery.record_lifecycle_request,
        heartbeat_ingester=lambda **kwargs: SimpleNamespace(observed=0, cancel_requested=0),
        monotonic_ns=lambda: 1000000,
        wall_time=lambda: 100.0,
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
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError, KeyError, AttributeError),
    )


def _maintenance_request(job_records, recovery):
    return InMemoryMaintenanceRequest(
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


def test_stage775_timeout_sweep_returns_retry_decision_evidence_directly():
    recovery = _RecoveryWithDecisionEvidence()
    result = enforce_inmemory_timeout_sweep(**_sweep_kwargs(recovery, _job_records()))

    stages = tuple(item.get("stage") for item in result.timeout_retry_evidence)
    assert "inmemory_retry_pending_publication" in stages
    assert "inmemory_timeout_retry_escalation" in stages
    retry_evidence = next(item for item in result.timeout_retry_evidence if item.get("stage") == "inmemory_retry_pending_publication")
    assert retry_evidence["final_json_must_record"] is True
    assert retry_evidence["checkpoint_must_record"] is True
    assert retry_evidence["replay_must_reproduce"] is True


def test_stage775_parent_maintenance_does_not_duplicate_retry_decision_evidence():
    recovery = _RecoveryWithDecisionEvidence()
    job_records = _job_records()

    result = run_inmemory_parent_maintenance(_maintenance_request(job_records, recovery))

    retry_evidence = tuple(
        item for item in result.timeout_retry_evidence if item.get("stage") == "inmemory_retry_pending_publication"
    )
    assert len(retry_evidence) == 1
    attached_retry_evidence = tuple(
        item for item in tuple(job_records[1].get("timeout_retry_evidence") or ())
        if item.get("stage") == "inmemory_retry_pending_publication"
    )
    assert len(attached_retry_evidence) == 1
