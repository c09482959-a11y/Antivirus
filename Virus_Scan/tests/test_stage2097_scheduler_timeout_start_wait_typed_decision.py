from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_start_wait_decisions import timeout_record_budget_snapshot
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_waits import (
    evaluate_assigned_start_wait,
    evaluate_queued_start_wait,
)

RECOVERABLE = (RuntimeError, TypeError, ValueError, OSError)


def _suppressed(_reason: str, _error: BaseException) -> None:
    return None


class FailingRecovery:
    def replace_with_history_transition(self, *args, **kwargs):
        raise RuntimeError("transition failed")


class RecordingRecovery:
    def __init__(self):
        self.calls = []

    def replace_with_history_transition(self, job_id, rec, reason, *, pid=None, now=None, action="history"):
        self.calls.append((job_id, reason, pid, now, action))
        return rec


class HostileDict(dict):
    def __contains__(self, key):
        raise AssertionError("contains hook should not run")

    def __getitem__(self, key):
        raise AssertionError("getitem hook should not run")


def test_stage2097_queued_start_wait_returns_typed_no_wait_decision_instead_of_zero_default():
    recovery = RecordingRecovery()
    rec = {"state": "queued"}
    evidence = []

    decision = evaluate_queued_start_wait(
        jid="job-1",
        rec=rec,
        now=10.0,
        recovery=recovery,
        queued_unstarted_count=0,
        max_queued_unstarted=2,
        queued_start_timeout_sec=5.0,
        start_wait_budget=lambda record, default: default,
        timeout_retry_evidence=evidence,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert decision.wait_delta == 0
    assert decision.state == "not_armed_backlog_available"
    assert decision.reason == "queued_timeout_armed"
    assert rec["queued_timeout_armed_at"] == 10.0
    assert recovery.calls == []
    assert evidence == []


def test_stage2097_queued_recovery_failure_records_typed_timeout_budget_unavailable():
    rec = {"state": "queued", "attempt": 3}
    evidence = []

    decision = evaluate_queued_start_wait(
        jid="job-2",
        rec=rec,
        now=20.0,
        recovery=FailingRecovery(),
        queued_unstarted_count=5,
        max_queued_unstarted=1,
        queued_start_timeout_sec=5.0,
        start_wait_budget=lambda record, default: default,
        timeout_retry_evidence=evidence,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert decision.wait_delta == 1
    assert decision.state == "not_armed_backlog_full"
    assert evidence
    timeout_budget = evidence[0]["timeout_budget"]
    assert timeout_budget["state"] == "timeout_budget_unavailable"
    assert timeout_budget["reason"] == "missing"
    assert timeout_budget["replay_must_reproduce"] is True


def test_stage2097_assigned_start_wait_returns_typed_missing_start_time_decision():
    rec = {"state": "assigned"}
    evidence = []

    decision = evaluate_assigned_start_wait(
        jid="job-3",
        rec=rec,
        now=50.0,
        recovery=RecordingRecovery(),
        assigned_start_timeout_sec=5.0,
        start_wait_budget=lambda record, default: default,
        timeout_retry_evidence=evidence,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert decision.wait_delta == 0
    assert decision.state == "missing_start_time"
    assert decision.reason == "assigned_start_wait_missing_assigned_at"
    assert evidence == []


def test_stage2097_timeout_budget_snapshot_rejects_hostile_mapping_without_hooks():
    budget = timeout_record_budget_snapshot(HostileDict())

    assert budget["state"] == "timeout_budget_unavailable"
    assert budget["reason"] == "unsupported_record"
    assert budget["record_type"] == "HostileDict"
