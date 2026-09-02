from __future__ import annotations

from typing import Any, cast

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import publish_cancel_payload
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import replace_with_history_transition

from collections import deque

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


def _worker_error_result(path, error):
    return {"file": str(path), "tags": [], "error": str(error), "scan_integrity": {}}


def _base_call(job_records, *, max_job_retries=0, worker_error_result=_worker_error_result):
    results = {}
    failed = set()
    terminal = set()
    decision = retry_or_fail(
        job_records=job_records,
        active={7: object()},
        pending=deque(),
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=7,
        reason="queue_worker_hard_timeout",
        max_job_retries=max_job_retries,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=worker_error_result,
        pid=123,
    )
    return decision, results, failed, terminal


def test_stage767_malformed_retry_attempt_records_contract_evidence_without_aborting_exhaustion():
    job_records = {7: {"file": "sample.bin", "attempt": "bad-attempt", "state": "running", "history": ()}}

    decision, results, failed, terminal = _base_call(job_records)

    assert decision.retried is False
    assert failed == {7}
    assert terminal == {7}
    record = job_records[7]
    assert record["retry_contract_failed"] is True
    evidence = record["retry_contract_failures"][0]
    assert evidence["field"] == "attempt"
    assert evidence["final_json_must_record"] is True
    output = results["sample.bin"]
    assert output["scan_integrity"]["inmemory_worker_failure_evidence"]["attempt"] == 0


def test_stage767_malformed_max_retries_records_contract_evidence_without_aborting_retry_path():
    job_records = {7: {"file": "sample.bin", "attempt": 0, "state": "running", "history": ()}}

    decision, results, failed, terminal = _base_call(job_records, max_job_retries=cast(Any, "bad-max"))

    assert decision.retried is False
    assert failed == {7}
    assert terminal == {7}
    evidence = job_records[7]["retry_contract_failures"][0]
    assert evidence["field"] == "max_job_retries"
    assert evidence["checkpoint_must_record"] is True
    assert results["sample.bin"]["scan_integrity"]["queue_failure"] is True


def test_stage767_nondict_worker_error_result_becomes_retry_exhaustion_evidence():
    job_records = {7: {"file": "sample.bin", "attempt": 1, "state": "running", "history": ()}}

    decision, results, failed, terminal = _base_call(
        job_records,
        max_job_retries=0,
        worker_error_result=lambda path, error: "not-a-dict-result",
    )

    assert decision.retried is False
    output = results["sample.bin"]
    assert output["retry_exhaustion_result_failed"] is True
    evidence = output["retry_exhaustion_result_evidence"]
    assert evidence["stage"] == "inmemory_retry_exhaustion_result"
    assert evidence["final_json_must_record"] is True
    assert output["scan_integrity"]["retry_exhaustion_result_failed"] is True


def test_stage767_malformed_retry_history_records_contract_evidence_without_aborting_result_history():
    job_records = {7: {"file": "sample.bin", "attempt": 1, "state": "running", "history": "bad-history"}}

    decision, results, failed, terminal = _base_call(job_records, max_job_retries=0)

    assert decision.retried is False
    record = job_records[7]
    evidence = [item for item in record["retry_contract_failures"] if item["field"] == "history"]
    assert evidence
    assert evidence[0]["replay_must_reproduce"] is True
    assert isinstance(results["sample.bin"]["scheduler_history"], tuple)


def test_stage767_invalid_cancel_flags_returns_cancel_publication_evidence_without_raising():

    result = publish_cancel_payload(
        job_id=7,
        reason="queue_worker_progress_stalled",
        generation=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        flags=cast(Any, "bad-flags"),
    )

    assert result.published is False
    assert result.evidence is not None
    record = dict(result.evidence.as_record())
    assert record["stage"] == "inmemory_retry_cancel_publication"
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage767_replace_history_transition_records_malformed_attempt_contract_evidence():

    job_records = {}
    updated = replace_with_history_transition(
        job_records=job_records,
        job_id=7,
        record={"file": "sample.bin", "attempt": "bad-attempt", "history": ()},
        reason="queue_worker_progress_stalled",
        pid=123,
        now=100.0,
        action="queued_wait",
    )

    failures = updated["retry_contract_failures"]
    assert failures[0]["field"] == "attempt"
    assert failures[0]["final_json_must_record"] is True
    assert job_records[7]["history"][-1]["action"] == "queued_wait"


def test_stage767_malformed_retry_pid_records_contract_evidence_without_aborting_exhaustion():
    job_records = {7: {"file": "sample.bin", "attempt": 1, "state": "running", "history": ()}}
    results = {}
    failed = set()
    terminal = set()

    decision = retry_or_fail(
        job_records=job_records,
        active={7: object()},
        pending=deque(),
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=7,
        reason="queue_worker_hard_timeout",
        max_job_retries=0,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=_worker_error_result,
        pid="bad-pid",
    )

    assert decision.retried is False
    output = results["sample.bin"]
    assert output["scan_integrity"]["inmemory_worker_failure_evidence"]["worker_pid"] == 0
    failures = output["scan_integrity"]["inmemory_retry_contract_failures"]
    assert any(item["field"] == "pid" for item in failures)
