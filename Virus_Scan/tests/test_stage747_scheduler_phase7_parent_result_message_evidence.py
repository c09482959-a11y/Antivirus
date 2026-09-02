from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from types import SimpleNamespace

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.orchestration.inmemory_parent_result import handle_next_inmemory_parent_result


class OneMessageQueue:
    def __init__(self, message):
        self.message = message

    def get(self, timeout=0.25):  # noqa: ARG002 - mirrors queue contract
        return self.message


class BadReprMessage:
    def __repr__(self):
        raise RuntimeError("repr exploded")


def _recovery():
    return SimpleNamespace(
        record_lifecycle_request=lambda *_args, **_kwargs: None,
        replace_with_history_transition=lambda _job_id, rec, *_args, **_kwargs: rec,
        request_cancel_only=lambda *_args, **_kwargs: None,
        retry_or_fail=lambda *_args, **_kwargs: True,
    )


def _has_failure_marker(marker: str) -> bool:
    snapshot = failure_snapshot()
    return any(marker in str(key) for key in snapshot["records"])


def _handle(message) -> bool:
    return handle_next_inmemory_parent_result(
        result_queue=OneMessageQueue(message),
        job_records={},
        active={},
        terminal=set(),
        failed=set(),
        done=set(),
        results=[],
        recovery=_recovery(),
        state_index=InMemorySchedulerStateIndex(),
        root=None,
        routing_evidence_context=None,
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_flags=SimpleNamespace(poisoned_or_retire_mask=4),
        partial_output_path=None,
        partial_output_every=0,
        started_at=0.0,
        progress_every=0,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        recoverable_exceptions=(Exception,),
    )


def test_malformed_parent_result_message_records_worker_owned_evidence():
    clear_failure_records()

    should_continue = _handle("not-a-worker-result-message")

    assert should_continue is False
    assert _has_failure_marker("inmemory_parent_worker_message_parent_result_malformed_failed")


def test_unrepresentable_parent_result_message_still_records_evidence():
    clear_failure_records()

    should_continue = _handle(BadReprMessage())

    assert should_continue is False
    assert _has_failure_marker("inmemory_parent_worker_message_parent_result_malformed_failed")
    assert not _has_failure_marker("inmemory_parent_worker_message_parent_result_validation_failed")
