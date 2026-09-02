from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import InMemoryTimeoutSweepResult, enforce_inmemory_timeout_sweep
from Virus_Scan.scheduler.timeout.timeout_budget import TimeoutBudget, compute_timeout_budget


ROOT = Path(__file__).resolve().parents[1] / "scheduler" / "timeout"


def test_stage797_timeout_sweep_is_decomposed_into_bounded_timeout_modules():
    assert (ROOT / "inmemory_timeout_sweep.py").read_text().count("def ") == 1
    assert (ROOT / "inmemory_timeout_sweep_waits.py").exists()
    assert (ROOT / "inmemory_timeout_sweep_running.py").exists()
    assert (ROOT / "inmemory_timeout_sweep_progress.py").exists()
    assert (ROOT / "inmemory_timeout_sweep_shared.py").exists()
    assert (ROOT / "inmemory_timeout_sweep_result.py").exists()
    for name in (
        "inmemory_timeout_sweep.py",
        "inmemory_timeout_sweep_waits.py",
        "inmemory_timeout_sweep_progress.py",
        "inmemory_timeout_sweep_result.py",
        "inmemory_timeout_sweep_shared.py",
    ):
        line_count = len((ROOT / name).read_text().splitlines())
        assert line_count <= 220, f"{name} remained oversized: {line_count} lines"


def test_stage797_timeout_sweep_public_contract_preserved_after_decomposition():
    class Recovery:
        def __init__(self):
            self.retries = []

        def replace_with_history_transition(self, job_id, rec, reason, pid=None, now=None, action="history", extra=None):
            return dict(rec)

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

        def request_cancel_only(self, job_id, reason, pid=None):
            return True

    recovery = Recovery()
    job_records = {
        1: {
                "state": "running",
                "pid": 44,
                "running_at": 1.0,
                "last_heartbeat": 99.0,
                "last_progress_time": 99.0,
                "attempt": 2,
                "timeout_budget": {"timeout_budget": 10.0, "heartbeat_stale_budget": 5.0, "stall_budget": 5.0},
        }
    }
    result = enforce_inmemory_timeout_sweep(
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
        update_ewma=lambda *args, **kwargs: None,
        ewma_state={},
        record_scheduler_suppressed=lambda *args, **kwargs: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
    )

    assert isinstance(result, InMemoryTimeoutSweepResult)
    assert result.hard_timeouts == 1
    assert recovery.retries == [(1, "queue_worker_hard_timeout", 44)]
    assert tuple(result.timeout_retry_evidence)


def test_stage797_timeout_budget_workload_classification_is_bounded_and_slotted(tmp_path):
    sample = tmp_path / "payload.rpy"
    sample.write_text("label start:\n    return\n", encoding="utf-8")

    budget = compute_timeout_budget(sample, configured_timeout_seconds=20)

    assert isinstance(budget, TimeoutBudget)
    assert budget.workload_class == "script_scan"
    assert not hasattr(budget, "__dict__")


def _state_index_for(job_records):
    index = InMemorySchedulerStateIndex()
    if type(job_records) is dict:
        for job_id, record in dict.items(job_records):
            if type(job_id) is int and type(record) is dict:
                index.sync_record(job_id, record, due_at=0.0)
    return index
