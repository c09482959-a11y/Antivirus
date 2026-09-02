from Virus_Scan.scheduler.queue.inmemory_empty_drain import requeue_missing_after_empty_drain
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import InMemoryRetryDecision


def test_empty_drain_preserves_retry_decision_evidence():
    evidence = {
        "stage": "inmemory_retry_result_publication",
        "job_id": 0,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_reproduce": True,
    }

    decision = requeue_missing_after_empty_drain(
        total_files=1,
        terminal=set(),
        retry_callable=lambda _job_id, _reason: InMemoryRetryDecision(False, 1, (evidence,)),
    )

    assert decision.completed_delta == 1
    assert decision.failed_now == 1
    assert decision.evidence == (evidence,)
