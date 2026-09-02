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

class _RecoveryWithRetryEvidence:
    completed = 0

    def __init__(self):
        self.evidence_journal = InMemoryRecoveryEvidenceJournal()
        self.evidence_journal.append_retry((
            {
                "stage": "preexisting_retry_evidence",
                "job_id": 1,
                "reason": "previous_sweep",
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_reproduce": True,
            },
        ))

    def retry_or_fail(self, job_id, reason, pid=None):
        self.evidence_journal.append_retry((
            {
                "stage": "inmemory_retry_pending_publication",
                "job_id": job_id,
                "reason": reason,
                "pid": pid,
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

    def replace_with_history_transition(self, job_id, rec, reason, pid=None, now=None, action="history", extra=None):
        updated = dict(rec)
        updated["history"] = tuple(updated.get("history") or ()) + (
            {"reason": reason, "pid": pid, "action": action, "extra": dict(extra or {})},
        )
        return updated


def _request(job_records, recovery):
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


def test_stage774_parent_maintenance_projects_new_retry_recovery_evidence_only():
    recovery = _RecoveryWithRetryEvidence()
    job_records = {
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

    result = run_inmemory_parent_maintenance(_request(job_records, recovery))

    returned_stages = tuple(item.get("stage") for item in result.timeout_retry_evidence)
    assert "inmemory_retry_pending_publication" in returned_stages
    assert "preexisting_retry_evidence" not in returned_stages
    attached_stages = tuple(
        item.get("stage") for item in tuple(job_records[1].get("timeout_retry_evidence") or ())
    )
    assert "inmemory_retry_pending_publication" in attached_stages
    assert job_records[1]["timeout_retry_evidence_recorded"] is True
