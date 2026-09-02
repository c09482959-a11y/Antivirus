from dataclasses import FrozenInstanceError
from pathlib import Path

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running_budget import build_running_timeout_budget_state
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity import enforce_worker_memory_toxicity
from Virus_Scan.scheduler.orchestration.inmemory_parent_timeout_maintenance import InMemoryTimeoutMaintenanceResult


def test_stage802_remaining_phase10_modules_stay_bounded_below_200_lines():
    scheduler_root = Path("Virus_Scan/scheduler")
    oversized = []
    for path in scheduler_root.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        if line_count >= 200:
            oversized.append((path.as_posix(), line_count))
    assert oversized == []


def test_stage802_running_timeout_budget_preserves_malformed_budget_evidence():
    failures = []
    state = build_running_timeout_budget_state(
        jid="j1",
        rec={"pid": 42, "running_at": 10.0, "last_heartbeat": 12.0, "last_progress_time": 13.0, "timeout_budget": "bad"},
        now=20.0,
        heartbeat_stale_sec=5.0,
        progress_stale_sec=6.0,
        base_pf_timeout=7.0,
        timeout_retry_evidence=failures,
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(Exception,),
    )
    assert state.pid == 42
    assert state.heartbeat_budget == 5.0
    assert state.progress_budget == 6.0
    assert state.hard_budget == 7.0
    assert failures[0]["reason"] == "timeout_budget_container_malformed"


def test_stage802_memory_toxicity_decomposition_preserves_cancel_failure_evidence():
    class CancelError(Exception):
        pass

    active = {1: {"pid": 99}}
    job_records = {1: {}}
    worker_metrics = {99: {"rss_mb": 512.0}}

    def cancel_job(*_args, **_kwargs):
        raise CancelError("cancel failed")

    cancelled = enforce_worker_memory_toxicity(
        procs=(),
        active=active,
        terminal=set(),
        worker_metrics=worker_metrics,
        rss_limit_mb=128.0,
        cancel_job=cancel_job,
        idle_worker_terminator=lambda **_kwargs: None,
        recoverable_exceptions=(CancelError,),
        record_suppressed=lambda *_args, **_kwargs: None,
        job_records=job_records,
    )
    assert cancelled == 0
    assert active[1]["memory_toxicity_failed"] is True
    assert job_records[1]["scan_integrity"]["memory_toxicity_escalation_failed"] is True
    assert worker_metrics[99]["memory_toxicity_failed"] is True
    assert active[1]["memory_toxicity_evidence"][0]["reason"] == "worker_memory_toxic_cancel_failed"


def test_stage802_timeout_maintenance_result_is_immutable_contract():
    result = InMemoryTimeoutMaintenanceResult(timeout_retry_evidence=({"reason": "r"},), timeout_reporting_failures=())
    assert result.timeout_retry_evidence == ({"reason": "r"},)
    try:
        result.timeout_retry_evidence = ()
    except FrozenInstanceError:
        pass
    else:  # pragma: no cover
        raise AssertionError("InMemoryTimeoutMaintenanceResult must be frozen")
