from Virus_Scan.scheduler.queue.inmemory_empty_drain import requeue_missing_after_empty_drain


def test_empty_drain_malformed_total_files_returns_immutable_retry_evidence():
    decision = requeue_missing_after_empty_drain(
        total_files=object(),
        terminal=set(),
        retry_callable=lambda *_args: (_ for _ in ()).throw(AssertionError("should not be called")),
    )

    assert decision.retried == 0
    assert decision.failed_now == 0
    assert decision.completed_delta == 0
    assert decision.evidence
    evidence = decision.evidence[0]
    assert evidence["stage"] == "inmemory_empty_drain_retry_recovery"
    assert evidence["reason"] == "missing_after_empty_drain_total_files"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True


def test_empty_drain_negative_total_files_records_evidence_without_hidden_clamp():
    decision = requeue_missing_after_empty_drain(
        total_files=-3,
        terminal=set(),
        retry_callable=lambda *_args: (_ for _ in ()).throw(AssertionError("should not be called")),
    )

    assert decision.evidence
    evidence = decision.evidence[0]
    assert evidence["reason"] == "missing_after_empty_drain_total_files"
    assert evidence["error_category"] == "ValueError"
    assert decision.retried == 0
