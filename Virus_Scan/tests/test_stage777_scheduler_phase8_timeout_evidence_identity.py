from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence_projection import attach_timeout_evidence_to_job_records
from Virus_Scan.scheduler.timeout.inmemory_timeout_retry_evidence import evidence_identity


def _base_evidence(**updates):
    record = {
        "stage": "inmemory_timeout_retry_escalation",
        "job_id": 9,
        "reason": "queue_worker_hard_timeout",
        "pid": 321,
        "attempt": 2,
        "action": "retry_or_fail_failed",
        "error_category": "RuntimeError",
        "error_source": "timeout.retry_or_fail",
        "detail": "retry escalation failed before publication",
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_reproduce": True,
    }
    record.update(updates)
    return record


def test_stage777_timeout_evidence_identity_keeps_distinct_failure_sources():
    first = _base_evidence(error_source="timeout.retry_or_fail", detail="retry escalation failed before publication")
    second = _base_evidence(error_source="timeout.result_publication", detail="retry result publication failed")

    assert evidence_identity(first) != evidence_identity(second)

    job_records = {9: {"history": ()}}
    attach_timeout_evidence_to_job_records(job_records=job_records, evidence_records=(first, second))

    attached = tuple(job_records[9].get("timeout_retry_evidence") or ())
    history = tuple(job_records[9].get("history") or ())
    assert len(attached) == 2
    assert len(history) == 2
    assert {item["error_source"] for item in attached} == {"timeout.retry_or_fail", "timeout.result_publication"}
    assert all(item["final_json_must_record"] is True for item in attached)
    assert all(item["checkpoint_must_record"] is True for item in attached)
    assert all(item["replay_must_reproduce"] is True for item in attached)


def test_stage777_timeout_evidence_identity_still_dedupes_exact_duplicate_failures():
    evidence = _base_evidence()
    duplicate = dict(evidence)

    job_records = {9: {"history": ()}}
    attach_timeout_evidence_to_job_records(job_records=job_records, evidence_records=(evidence, duplicate))

    attached = tuple(job_records[9].get("timeout_retry_evidence") or ())
    history = tuple(job_records[9].get("history") or ())
    assert len(attached) == 1
    assert len(history) == 1
