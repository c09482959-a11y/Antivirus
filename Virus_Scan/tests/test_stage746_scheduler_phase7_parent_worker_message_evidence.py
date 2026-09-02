from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from types import SimpleNamespace

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.orchestration.inmemory_parent_message import (
    InMemoryParentMessageRequest,
    handle_inmemory_parent_message,
)
from Virus_Scan.scheduler.workers.inmemory_parent_message_evidence import (
    InMemoryParentWorkerMessageFailureEvidence,
)


class RaisingActive(dict):
    def __bool__(self):
        return True

    def items(self):
        raise RuntimeError("active worker map failed")


class HeartbeatFlags:
    poisoned_or_retire_mask = 4


def _request(message, *, active=None):
    recovery = SimpleNamespace(
        record_lifecycle_request=lambda *_args, **_kwargs: None,
        replace_with_history_transition=lambda _job_id, rec, *_args, **_kwargs: rec,
        request_cancel_only=lambda *_args, **_kwargs: None,
        retry_or_fail=lambda *_args, **_kwargs: True,
    )
    return InMemoryParentMessageRequest(
        message=message,
        job_records={},
        active={} if active is None else active,
        terminal=set(),
        failed=set(),
        done=set(),
        results=[],
        recovery=recovery,
        state_index=InMemorySchedulerStateIndex(),
        root=None,
        routing_evidence_context=None,
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_flags=HeartbeatFlags(),
        partial_output_path=None,
        partial_output_every=0,
        partial_writer=None,
        started_at=0.0,
        progress_every=0,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        wall_time=lambda: 1.0,
        sleep=lambda _seconds: None,
        recoverable_exceptions=(Exception,),
    )


def _has_failure_marker(marker: str) -> bool:
    snapshot = failure_snapshot()
    return any(marker in str(key) for key in snapshot["records"])


def test_bad_assigned_worker_message_records_worker_owned_evidence():
    clear_failure_records()

    result = handle_inmemory_parent_message(_request(("assigned",)))

    assert result.handled is True
    assert result.should_continue is True
    assert _has_failure_marker("inmemory_parent_worker_message_assigned_failed")


def test_bad_heartbeat_worker_message_records_worker_owned_evidence():
    clear_failure_records()

    result = handle_inmemory_parent_message(_request(("heartbeat",)))

    assert result.handled is True
    assert result.should_continue is True
    assert _has_failure_marker("inmemory_parent_worker_message_heartbeat_failed")


def test_worker_exit_reconciliation_exception_records_worker_owned_evidence():
    clear_failure_records()

    result = handle_inmemory_parent_message(_request(("worker_exit", None, None, 123, 1.0), active=RaisingActive()))

    assert result.handled is True
    assert result.should_continue is True
    assert _has_failure_marker("inmemory_parent_worker_message_worker_exit_failed")



def test_unmatched_assigned_worker_message_records_rejection_evidence():
    clear_failure_records()

    result = handle_inmemory_parent_message(_request(("assigned", 9, "missing.bin", 123, 1.0, 0)))

    assert result.handled is True
    assert result.should_continue is False
    assert _has_failure_marker("inmemory_parent_worker_message_assigned_rejected_failed")


def test_unmatched_running_worker_message_records_rejection_evidence():
    clear_failure_records()

    result = handle_inmemory_parent_message(_request(("running", 9, "missing.bin", 123, 1.0, 0, 44)))

    assert result.handled is True
    assert result.should_continue is False
    assert _has_failure_marker("inmemory_parent_worker_message_running_rejected_failed")


def test_unmatched_heartbeat_worker_message_records_rejection_evidence():
    clear_failure_records()

    result = handle_inmemory_parent_message(
        _request(("heartbeat", 9, "missing.bin", 123, 1.0, 0, 1, "scan", 0, 0, 0))
    )

    assert result.handled is True
    assert result.should_continue is False
    assert _has_failure_marker("inmemory_parent_worker_message_heartbeat_rejected_failed")


def test_parent_worker_message_failure_evidence_context_is_immutable_metadata():
    evidence = InMemoryParentWorkerMessageFailureEvidence(
        message_kind="heartbeat",
        operation="heartbeat",
        message_preview="('heartbeat',)",
        reason="ValueError: malformed",
    )

    context = evidence.as_context()
    assert context["inmemory_parent_worker_message_failed"] is True
    assert context["inmemory_parent_worker_message_kind"] == "heartbeat"
    assert context["inmemory_parent_worker_message_operation"] == "heartbeat"
    assert "malformed" in str(context["inmemory_parent_worker_message_failure_reason"])
