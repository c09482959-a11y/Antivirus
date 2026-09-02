from typing import Any, cast

from Virus_Scan.scheduler.queue.raw_retry_job import prepare_raw_retry_job
from Virus_Scan.scheduler.queue.recovery_contract import (
    build_inmemory_retry_transition,
    retry_already_pending,
    build_recovery_duplicate_ignored_transition,
    reset_queue_retry_runtime_metadata,
    cancel_payload,
)
from Virus_Scan.scheduler.queue.orphan_recovery import _queue_reset_retry_runtime_metadata


def _any_mapping(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value)


def _record_items(value: object) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], value)


def test_stage102_inmemory_retry_is_idempotent_for_overlap():
    rec = {"file": "sample.bin", "attempt": 0, "state": "running", "pid": 123, "started_at": 10.0}
    transition = build_inmemory_retry_transition(rec, "worker_heartbeat_lost", pid=123, now=100.0)
    rec = _any_mapping(transition.as_record())
    assert transition.old_generation == 0
    assert transition.new_generation == 1
    assert rec["state"] == "pending_retry"
    assert rec["attempt"] == 1
    assert retry_already_pending(rec) is True
    duplicate_transition = build_recovery_duplicate_ignored_transition(rec, "worker_heartbeat_lost", pid=123, now=101.0)
    rec = _any_mapping(duplicate_transition.as_record())
    assert rec["attempt"] == 1
    assert _record_items(rec["history"])[-1]["action"] == "duplicate_recovery_ignored"


def test_stage102_cancel_payload_is_structured_and_deterministic():
    payload = cancel_payload("timeout", 2, now=50.0)
    assert payload["generation"] == 2
    assert payload["flags"] != 0
    assert payload["reason"] == "timeout"
    assert payload["iso"] == "1970-01-01T00:00:50Z"


def test_stage102_process_queue_retry_reset_uses_canonical_contract():
    job = {
        "file": "x.exe",
        "worker_pid": 444,
        "claimed_by": "worker-a",
        "heartbeat_time": 99,
        "queue_info": {
            "worker_pid": 444,
            "heartbeat_time": 99,
            "claim_path": "active/job.json",
            "retry_generation": 7,
        },
    }
    out = _queue_reset_retry_runtime_metadata(job, now=200.0, reason="requeued_after_stall")
    qi = _any_mapping(out["queue_info"])
    assert "worker_pid" not in out
    assert "claimed_by" not in out
    assert "worker_pid" not in qi
    assert "heartbeat_time" not in qi
    assert qi["retry_generation"] == 8
    assert qi["retry_pending_active"] is True
    assert qi["retry_pending_iso"] == "1970-01-01T00:03:20Z"


def test_stage102_raw_retry_job_cannot_be_double_armed():
    job = {"job_type": "raw_stage", "file": "x.bin", "file_id": "f1", "attempt": 0, "max_retries": 2, "worker_pid": 9}
    retry = prepare_raw_retry_job(job, {"error": "temporary raw failure"}, now=10.0)
    assert retry is not None
    assert retry["attempt"] == 1
    assert retry["retry_pending_active"] is True
    assert retry["raw_retry_from_attempt"] == 0
    second = prepare_raw_retry_job(retry, {"error": "same overlapping failure"}, now=11.0)
    assert second is None


def test_stage102_reset_queue_retry_runtime_metadata_matches_public_wrapper():
    job = {"queue_info": {"retry_generation": 0, "owner_pid": 12}, "active_claim": "a"}
    assert reset_queue_retry_runtime_metadata(job, now=1.0, reason="unit") == _queue_reset_retry_runtime_metadata(job, now=1.0, reason="unit")


def test_stage1926_recovery_contract_missing_inputs_are_explicit_not_defaulted():
    recovery_record = _any_mapping(build_recovery_duplicate_ignored_transition(
        {"attempt": 1, "state": "pending_retry", "retry_pending_generation": 1, "retry_pending_active": True},
        None,
        pid=123,
        now=20.0,
    ).as_record())
    history = _record_items(recovery_record["history"])[-1]
    assert history["reason"] == "missing_recovery_reason"

    retry = _any_mapping(build_inmemory_retry_transition({"attempt": 0, "state": "running"}, None, now=21.0).as_record())
    assert retry["retry_pending_reason"] == "missing_retry_reason"
    assert _record_items(retry["history"])[-1]["reason"] == "missing_recovery_reason"

    payload = cancel_payload(None, 2, now=22.0)
    assert payload["reason"] == "missing_recovery_reason"

    reset = reset_queue_retry_runtime_metadata({"queue_info": {}}, now=23.0, reason=None)
    assert _any_mapping(reset["queue_info"])["retry_pending_reason"] == "missing_recovery_reason"


def test_stage1926_recovery_contract_rejects_hostile_text_without_hooks():
    class HostileText:
        def __str__(self):  # pragma: no cover - must not be invoked
            raise AssertionError("caller-owned __str__ executed")

        def __format__(self, spec):  # pragma: no cover - must not be invoked
            raise AssertionError("caller-owned __format__ executed")

        @property
        def text(self):  # pragma: no cover - must not be invoked
            raise AssertionError("caller-owned property executed")

    transition = build_inmemory_retry_transition({"attempt": 0, "state": "running"}, HostileText(), now=24.0)
    out = _any_mapping(transition.as_record())
    assert cast(str, out["retry_pending_reason"]).startswith("<HostileText unsupported_retry_reason")
    assert cast(str, _record_items(out["history"])[-1]["reason"]).startswith("<HostileText unsupported_recovery_reason")

    payload = cancel_payload(HostileText(), 1, now=25.0)
    assert cast(str, payload["reason"]).startswith("<HostileText unsupported_recovery_reason")


def test_stage1926_recovery_integer_defaults_without_hostile_hooks():
    class HostileInteger:
        touched = 0

        def __int__(self):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __int__ executed")

        def __str__(self):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __str__ executed")

    payload = cancel_payload("timeout", HostileInteger(), now=26.0)
    assert payload["generation"] == 0
    generation_issue = _any_mapping(payload["generation_issue"])
    assert generation_issue["error_category"] == "recovery_generation_rejected"
    assert generation_issue["value_type"] == "HostileInteger"
    assert HostileInteger.touched == 0


def test_stage1927_recovery_integer_rejections_record_explicit_evidence():
    class HostileInteger:
        touched = 0

        def __int__(self):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __int__ executed")

        def __str__(self):  # pragma: no cover - must not be invoked
            type(self).touched += 1
            raise AssertionError("caller-owned __str__ executed")

    retry = _any_mapping(build_inmemory_retry_transition({"attempt": HostileInteger(), "state": "running"}, "timeout", now=27.0).as_record())
    assert retry["attempt"] == 1
    assert _any_mapping(retry["attempt_issue"])["error_category"] == "retry_attempt_rejected"
    assert _any_mapping(_record_items(retry["history"])[-1]["attempt_issue"])["error_category"] == "recovery_attempt_rejected"

    reset = reset_queue_retry_runtime_metadata({"queue_info": {"retry_generation": HostileInteger()}}, now=28.0, reason="retry")
    reset_queue_info = _any_mapping(reset["queue_info"])
    assert reset_queue_info["retry_generation"] == 1
    assert _any_mapping(reset_queue_info["retry_generation_issue"])["error_category"] == "retry_generation_rejected"
    assert HostileInteger.touched == 0
