from Virus_Scan.scheduler.queue.recovery_contract import build_inmemory_retry_transition, retry_already_pending
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import (
    mark_retry_admitted_decision,
    terminal_transition_decision,
)


def test_stage_w_retry_pending_cleared_when_generation_admitted():
    rec = {"file": "sample.bin", "attempt": 0, "generation": 0, "state": "running", "history": []}
    transition = build_inmemory_retry_transition(rec, "worker_died", pid=123, now=10.0)
    rec = transition.as_record()
    assert transition.old_generation == 0
    assert transition.new_generation == 1
    assert retry_already_pending(rec) is True

    assert mark_retry_admitted_decision(rec, attempt=1, now=11.0).accepted is True
    assert rec["state"] == "pending_retry"  # caller owns actual queued/running state mutation
    assert rec["retry_pending_active"] is False
    assert rec["retry_admitted_generation"] == 1
    assert retry_already_pending(rec) is False


def test_stage_w_stale_retry_generation_not_admitted():
    rec = {"attempt": 2, "state": "pending_retry", "retry_pending_generation": 2, "retry_pending_active": True}
    assert mark_retry_admitted_decision(rec, attempt=1, now=20.0).accepted is False
    assert rec["retry_pending_active"] is True
    assert retry_already_pending(rec) is True


def test_stage_w_terminal_transition_clears_retry_pending_state():
    rec = {"attempt": 3, "state": "running", "retry_pending_generation": 3, "retry_pending_active": True}
    assert terminal_transition_decision(rec, state="done", attempt=3, now=30.0).accepted is True
    assert rec["state"] == "done"
    assert rec["retry_pending_active"] is False
    assert rec["terminal_time"] == 30.0
