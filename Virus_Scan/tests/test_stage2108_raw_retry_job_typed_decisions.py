from __future__ import annotations

from Virus_Scan.scheduler.queue.raw_retry_job import prepare_raw_retry_job, raw_retry_job_decision
from Virus_Scan.scheduler.queue.raw_retry_job_decisions import raw_retry_mapping_decision, raw_retry_timestamp_decision


class HostileValue:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile bool hook touched")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile str hook touched")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile repr hook touched")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile int hook touched")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile float hook touched")


class HostileMapping(dict):
    def get(self, *_args, **_kwargs):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping get touched")

    def __iter__(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping iter touched")

    def __bool__(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping bool touched")


def test_stage2108_raw_retry_rejections_are_typed_and_replayable() -> None:
    rejected_mapping = raw_retry_job_decision(HostileMapping(attempt=0), {"error": "boom"}, now=1.0)
    exhausted = raw_retry_job_decision({"attempt": 2, "max_retries": 2}, {"error": "done"}, now=1.0)
    prepared = raw_retry_job_decision(
        {"job_type": "raw_stage", "file": "x.bin", "file_id": "f1", "attempt": 0, "max_retries": 2},
        HostileMapping(error=HostileValue()),
        now=HostileValue(),
    )

    assert rejected_mapping.accepted is False
    assert rejected_mapping.reason == "raw_retry_job_mapping_rejected"
    assert rejected_mapping.retry_job is None
    assert exhausted.reason == "raw_retry_attempts_exhausted"
    assert exhausted.retry_job is None
    assert prepared.accepted is True
    assert prepared.result_mapping_reason == "raw_retry_result_mapping_rejected"
    assert prepared.timestamp_reason == "raw_retry_timestamp_rejected"
    assert prepared.retry_job is not None
    assert prepared.retry_job["attempt"] == 1
    assert prepared.retry_job["retry_pending_reason"] == "raw_retry"
    assert prepared.retry_job["last_error"] == ""
    assert prepare_raw_retry_job({"attempt": 2, "max_retries": 2}, {"error": "done"}) is None


def test_stage2108_raw_retry_legacy_projection_preserves_retry_record() -> None:
    retry = prepare_raw_retry_job(
        {"job_type": "raw_stage", "file": "x.bin", "file_id": "f1", "attempt": 0, "max_retries": 2, "worker_pid": 9},
        {"error": "temporary raw failure"},
        now=10.0,
    )

    assert retry is not None
    assert retry["attempt"] == 1
    assert retry["retry_pending_active"] is True
    assert retry["retry_pending_reason"] == "temporary raw failure"
    assert retry["raw_retry_from_attempt"] == 0
    assert retry["job_type"] == "raw_stage"
    assert raw_retry_job_decision(retry, {"error": "duplicate"}, now=11.0).reason == "raw_retry_already_pending"
    assert prepare_raw_retry_job(retry, {"error": "duplicate"}, now=11.0) is None


def test_stage2108_raw_retry_no_hook_decisions_do_not_call_hostile_protocols() -> None:
    HostileValue.touched = 0
    mapping = raw_retry_mapping_decision(HostileMapping(attempt=0), rejected_reason="mapping_rejected")
    timestamp = raw_retry_timestamp_decision(HostileValue())
    retry = prepare_raw_retry_job(
        {"job_type": "raw_stage", "file": "x.bin", "file_id": "f1", "attempt": 0, "max_retries": 2, "worker_pid": HostileValue()},
        {"error": HostileValue()},
        now=HostileValue(),
    )

    assert mapping.accepted is False
    assert timestamp.accepted is False
    assert retry is not None
    assert retry["retry_pending_reason"] == "raw_retry"
    assert retry["last_error"] == ""
    assert HostileValue.touched == 0
