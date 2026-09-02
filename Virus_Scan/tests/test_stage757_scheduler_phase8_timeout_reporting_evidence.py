from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

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
        self.cancels = []

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
        raise AssertionError("retry_or_fail should not be reached for this progress-stall test")

    def request_cancel_only(self, job_id, reason, pid=None):
        self.cancels.append((job_id, reason, pid))
        return True


def _base_kwargs(recovery, job_records, *, record_scheduler_suppressed, update_ewma):
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
        update_ewma=update_ewma,
        ewma_state={},
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
    )


def test_stage757_progress_stall_reporting_failure_is_evidence_even_when_suppression_succeeds():
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
    suppressed = []

    def update_ewma(*_args, **_kwargs):
        raise RuntimeError("ewma update failed but suppression succeeded")

    result = enforce_inmemory_timeout_sweep(
        **_base_kwargs(
            recovery,
            job_records,
            record_scheduler_suppressed=lambda name, exc: suppressed.append((name, str(exc))),
            update_ewma=update_ewma,
        )
    )

    assert result.progress_stalls == 1
    assert recovery.cancels == [(1, "queue_worker_progress_stalled", 44)]
    assert suppressed and "ewma update failed" in suppressed[0][1]
    reporting = tuple(result.timeout_reporting_failures)
    assert reporting
    assert reporting[0]["stage"] == "inmemory_timeout_reporting"
    assert reporting[0]["reason"] == "progress_stall_reporting_failed"
    assert reporting[0]["error_category"] == "RuntimeError"
    assert reporting[0]["final_json_must_record"] is True
    assert reporting[0]["checkpoint_must_record"] is True
    assert reporting[0]["replay_must_reproduce"] is True
