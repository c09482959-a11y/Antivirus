from types import MappingProxyType
from typing import cast

from Virus_Scan.scheduler.queue.raw_retry_job import prepare_raw_retry_job
from Virus_Scan.scheduler.queue.recovery_contract import (
    build_inmemory_retry_transition,
    build_recovery_duplicate_ignored_transition,
    retry_already_pending,
)


def test_stage537_inmemory_retry_transition_is_immutable_output_and_preserves_source():
    source = {"file": "sample.bin", "attempt": 0, "state": "running", "pid": 123, "history": []}
    transition = build_inmemory_retry_transition(source, "worker_died", pid=123, now=10.0)

    assert source == {"file": "sample.bin", "attempt": 0, "state": "running", "pid": 123, "history": []}
    assert isinstance(transition.record, MappingProxyType)
    updated = transition.as_record()
    assert updated["attempt"] == 1
    assert updated["generation"] == 1
    assert updated["state"] == "pending_retry"
    assert retry_already_pending(updated) is True
    history = cast(list[dict[str, object]], updated["history"])
    assert history[-1]["action"] == "retry"


def test_stage537_duplicate_recovery_transition_is_immutable_evidence_only():
    source = {"file": "sample.bin", "attempt": 1, "state": "pending_retry", "retry_pending_generation": 1, "retry_pending_active": True, "history": []}
    transition = build_recovery_duplicate_ignored_transition(source, "worker_died", pid=123, now=11.0)

    assert source["history"] == []
    updated = transition.as_record()
    assert updated["attempt"] == 1
    assert updated["retry_pending_active"] is True
    history = cast(list[dict[str, object]], updated["history"])
    assert history[-1]["action"] == "duplicate_recovery_ignored"


def test_stage537_raw_retry_job_uses_immutable_transition_without_source_mutation():
    job = {"job_type": "raw_stage", "file": "x.bin", "file_id": "f1", "attempt": 0, "max_retries": 2, "worker_pid": 9}
    retry = prepare_raw_retry_job(job, {"error": "temporary raw failure"}, now=12.0)

    assert job["attempt"] == 0
    assert "retry_pending_active" not in job
    assert retry is not None
    assert retry["attempt"] == 1
    assert retry["raw_retry_from_attempt"] == 0
    assert retry_already_pending(retry) is True
