from __future__ import annotations

from Virus_Scan.scheduler.queue.inmemory_empty_drain import requeue_missing_after_empty_drain
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import InMemoryRetryDecision


def test_stage761_empty_drain_decision_is_immutable_contract():
    decision = requeue_missing_after_empty_drain(
        total_files=2,
        terminal={0},
        retry_callable=lambda job_id, reason: InMemoryRetryDecision(True, 0),
    )

    assert decision.retried == 1
    assert decision.failed_now == 0
    assert decision.completed_delta == 0
    assert decision.evidence == ()


def test_stage761_empty_drain_retry_callable_failure_is_explicit_evidence():
    decision = requeue_missing_after_empty_drain(
        total_files=1,
        terminal=set(),
        retry_callable=lambda job_id, reason: (_ for _ in ()).throw(RuntimeError("retry unavailable")),
    )

    assert decision.retried == 0
    assert decision.failed_now == 1
    assert decision.completed_delta == 0
    assert decision.evidence
    evidence = decision.evidence[0]
    assert evidence["stage"] == "inmemory_empty_drain_retry_recovery"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    assert evidence["retry_failure"] is True
