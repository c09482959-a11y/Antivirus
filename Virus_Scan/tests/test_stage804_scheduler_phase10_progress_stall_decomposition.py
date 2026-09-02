from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from Virus_Scan.scheduler.timeout import inmemory_timeout_sweep_progress as progress

from pathlib import Path
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

    def retry_or_fail(self, job_id, reason, pid=None):
        self.retries.append((job_id, reason, pid))
        return None

    def request_cancel_only(self, job_id, reason, pid=None):
        self.cancels.append((job_id, reason, pid))
        return True


def _base_kwargs(recovery, job_records, now=100.0):
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
        heartbeat_ingester=lambda **kwargs: SimpleNamespace(observed=0, cancel_requested=0),
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


def test_stage804_progress_stall_decisions_are_split_into_bounded_timeout_modules():
    timeout_root = Path("Virus_Scan/scheduler/timeout")
    progress_source = (timeout_root / "inmemory_timeout_sweep_progress.py").read_text()
    cancel_source = (timeout_root / "inmemory_timeout_sweep_progress_cancel.py").read_text()
    preexec_source = (timeout_root / "inmemory_timeout_sweep_progress_preexecution.py").read_text()

    assert "handle_pre_execution_progress_wait" in progress_source
    assert "evaluate_progress_stall_cancellation" in progress_source
    assert "record_progress_stall_cancel" not in progress_source
    assert "request_cancel_only" in cancel_source
    assert "pre_execution_progress_wait_no_retry" in preexec_source


def test_stage804_progress_stall_public_exports_are_canonical():

    assert progress.__all__ == ("evaluate_running_progress_stall",)
    assert hasattr(progress, "evaluate_running_progress_stall")
    assert not hasattr(progress, "evaluate_running_timeout_state")


def test_stage804_pre_execution_progress_wait_still_records_wait_without_retry_or_cancel():
    recovery = _Recovery()
    job_records = {
        1: {
            "state": "running",
            "pid": 44,
            "running_at": 90.0,
            "last_heartbeat": 99.0,
            "last_progress_time": 1.0,
            "attempt": 1,
            "stage": "queued_preparation",
            "timeout_budget": {"timeout_budget": 1000.0, "heartbeat_stale_budget": 500.0, "stall_budget": 5.0},
        }
    }
    kwargs = _base_kwargs(recovery, job_records)
    kwargs["stage_is_pre_execution"] = lambda stage: stage == "queued_preparation"

    result = enforce_inmemory_timeout_sweep(**kwargs)

    assert result.progress_stalls == 1
    assert result.cancelled_after_stall == 0
    assert recovery.transitions == [(1, "pre_execution_progress_wait_no_retry", 44, "pre_execution_wait")]
    assert recovery.cancels == []
    assert recovery.retries == []
