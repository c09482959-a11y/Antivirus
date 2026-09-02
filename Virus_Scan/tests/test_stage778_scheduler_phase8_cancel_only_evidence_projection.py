from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from collections import deque
from types import SimpleNamespace

from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import enforce_inmemory_timeout_sweep



def _state_index_for(job_records):
    index = InMemorySchedulerStateIndex()
    if type(job_records) is dict:
        for job_id, record in dict.items(job_records):
            if type(job_id) is int and type(record) is dict:
                index.sync_record(job_id, record, due_at=0.0)
    return index

class _FailingCancelSlots:
    def __setitem__(self, key, value):
        raise RuntimeError("cancel publication denied")


class _LifecycleJournal:
    def record(self, *args, **kwargs):
        return None


def _worker_error_result(path, exc):
    return {"file": str(path), "tags": [], "error": str(exc), "scan_integrity": {}}


def _heartbeat_ingester(**kwargs):
    return SimpleNamespace(observed=0, cancel_requested=0)


def _record_suppressed(_category, _exc):
    return None


def _update_ewma(*args, **kwargs):
    return None


def test_stage778_timeout_cancel_only_projects_queue_cancel_publication_evidence():
    job_records = {
        1: {
            "file": "sample.bin",
            "attempt": 0,
            "state": "running",
            "pid": 55,
            "running_at": 99.0,
            "last_heartbeat": 100.0,
            "last_progress_time": 1.0,
            "stage": "raw_scan",
            "history": (),
            "timeout_budget": {"timeout_budget": 1000.0, "heartbeat_stale_budget": 1000.0, "stall_budget": 1.0},
        }
    }
    active = {1: {"pid": 55}}
    state_index = _state_index_for(job_records)
    recovery = InMemoryRecoveryCoordinator(
        state_index=state_index,
        job_records=job_records,
        active=active,
        pending=deque(),
        results={},
        failed=set(),
        terminal=set(),
        lifecycle_journal=_LifecycleJournal(),
        max_job_retries=1,
        cancel_table=None,
        cancel_generation=_FailingCancelSlots(),
        cancel_flags=_FailingCancelSlots(),
        cancel_stall_poison_mask=3,
        total_files=1,
        worker_error_result=_worker_error_result,
    )

    result = enforce_inmemory_timeout_sweep(
        state_index=state_index,
        job_records=job_records,
        active=active,
        terminal=set(),
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_table=None,
        heartbeat_flags=None,
        read_heartbeat=lambda **_kwargs: None,
        cancel_job=recovery.request_cancel_only,
        lifecycle_recorder=recovery.record_lifecycle_request,
        heartbeat_ingester=_heartbeat_ingester,
        monotonic_ns=lambda: 0,
        wall_time=lambda: 100.0,
        recovery=recovery,
        max_queued_unstarted=100,
        queued_start_timeout_sec=1000.0,
        assigned_start_timeout_sec=1000.0,
        heartbeat_stale_sec=1000.0,
        progress_stale_sec=1.0,
        base_pf_timeout=1000.0,
        cancel_grace_sec=1000.0,
        start_wait_budget=lambda _record, default: default,
        stage_is_pre_execution=lambda _stage: False,
        update_ewma=_update_ewma,
        ewma_state={},
        record_scheduler_suppressed=_record_suppressed,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError, AttributeError),
    )

    stages = [record.get("stage") for record in result.timeout_retry_evidence]
    assert "inmemory_retry_cancel_publication" in stages
    assert "inmemory_timeout_retry_escalation" in stages
    cancel_records = tuple(
        record for record in result.timeout_retry_evidence if record.get("stage") == "inmemory_retry_cancel_publication"
    )
    assert len(cancel_records) == 1
    cancel_record = cancel_records[0]
    assert cancel_record["job_id"] == 1
    assert cancel_record["reason"] == "queue_worker_progress_stalled"
    assert cancel_record["final_json_must_record"] is True
    assert cancel_record["checkpoint_must_record"] is True
    assert cancel_record["replay_must_reproduce"] is True
    assert recovery.cancel_evidence_snapshot() == cancel_records


def test_stage778_cancel_only_evidence_projection_is_idempotent_per_recovery_record():
    job_records = {
        2: {"file": "sample.bin", "attempt": 0, "state": "running", "history": ()}
    }
    state_index = _state_index_for(job_records)
    recovery = InMemoryRecoveryCoordinator(
        state_index=state_index,
        job_records=job_records,
        active={2: {"pid": 66}},
        pending=deque(),
        results={},
        failed=set(),
        terminal=set(),
        lifecycle_journal=_LifecycleJournal(),
        max_job_retries=1,
        cancel_table=None,
        cancel_generation=_FailingCancelSlots(),
        cancel_flags=_FailingCancelSlots(),
        cancel_stall_poison_mask=3,
        total_files=1,
        worker_error_result=_worker_error_result,
    )

    assert recovery.request_cancel_only(2, "queue_worker_progress_stalled", pid=66) is True
    assert recovery.request_cancel_only(2, "queue_worker_progress_stalled", pid=66) is True

    assert len(recovery.cancel_evidence_snapshot()) == 1
    record = recovery.cancel_evidence_snapshot()[0]
    assert record["stage"] == "inmemory_retry_cancel_publication"
    assert record["error_category"] in {"RuntimeError", "cancel_publication_failed"}
