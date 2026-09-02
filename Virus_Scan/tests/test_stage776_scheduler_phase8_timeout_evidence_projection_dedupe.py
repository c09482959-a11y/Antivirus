from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence_projection import attach_timeout_evidence_to_job_records


def _evidence():
    return {
        "stage": "inmemory_timeout_retry_escalation",
        "job_id": 7,
        "reason": "queue_worker_hard_timeout",
        "pid": 123,
        "action": "retry_or_fail",
        "timeout_failure": True,
        "retry_failure": True,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_reproduce": True,
    }


def test_stage776_timeout_retry_evidence_projection_is_idempotent_for_same_event():
    job_records = {7: {"history": ()}}
    evidence = _evidence()

    attach_timeout_evidence_to_job_records(job_records=job_records, evidence_records=(evidence,))
    attach_timeout_evidence_to_job_records(job_records=job_records, evidence_records=(dict(evidence),))

    attached = tuple(job_records[7].get("timeout_retry_evidence") or ())
    history = tuple(job_records[7].get("history") or ())
    assert len(attached) == 1
    assert len(history) == 1
    assert attached[0]["final_json_must_record"] is True
    assert attached[0]["checkpoint_must_record"] is True
    assert attached[0]["replay_must_reproduce"] is True


def test_stage776_timeout_retry_evidence_projection_dedupes_duplicates_in_same_batch():
    job_records = {"7": {"history": ()}}
    evidence = _evidence()

    attach_timeout_evidence_to_job_records(
        job_records=job_records,
        evidence_records=(dict(evidence), dict(evidence)),
    )

    attached = tuple(job_records["7"].get("timeout_retry_evidence") or ())
    history = tuple(job_records["7"].get("history") or ())
    assert len(attached) == 1
    assert len(history) == 1
    assert attached[0]["job_id"] == 7
