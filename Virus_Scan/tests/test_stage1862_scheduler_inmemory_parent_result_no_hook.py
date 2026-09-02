from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.tests.support.static_inventory import read_python_file


"""Stage1862 in-memory parent result no-hook regressions."""
from pathlib import Path
import queue

from Virus_Scan.scheduler.orchestration.inmemory_parent_result import (
    _is_parent_result_message,
    _malformed_parent_result_log_message,
    handle_next_inmemory_parent_result,
)


class EmptyQueue:
    def get(self, *, timeout):
        raise queue.Empty


class MessageQueue:
    def __init__(self, message):
        self.message = message

    def get(self, *, timeout):
        return self.message


class HostileMessage:
    touched = False

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("message len hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("message bool hook executed")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("message iter hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("message repr hook executed")

    def __format__(self, format_spec):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("message format hook executed")


class HostileList(list):
    touched = False

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("list-subclass len hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("list-subclass repr hook executed")

    def __format__(self, format_spec):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("list-subclass format hook executed")


def _handle_with_message(message):
    return handle_next_inmemory_parent_result(
        result_queue=MessageQueue(message),
        job_records={},
        active={},
        terminal=set(),
        failed=set(),
        done=set(),
        results={},
        recovery=None,
        state_index=InMemorySchedulerStateIndex(),
        root=".",
        routing_evidence_context={},
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_flags={},
        partial_output_path=None,
        partial_output_every=10,
        started_at=0.0,
        progress_every=10,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        recoverable_exceptions=(Exception,),
    )


def test_empty_queue_returns_false_outside_exception_sentinel_route():
    assert handle_next_inmemory_parent_result(
        result_queue=EmptyQueue(),
        job_records={},
        active={},
        terminal=set(),
        failed=set(),
        done=set(),
        results={},
        recovery=None,
        state_index=InMemorySchedulerStateIndex(),
        root=".",
        routing_evidence_context={},
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_flags={},
        partial_output_path=None,
        partial_output_every=10,
        started_at=0.0,
        progress_every=10,
        throttle_sec=0.0,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        recoverable_exceptions=(Exception,),
    ) is False


def test_malformed_hostile_message_is_rejected_without_hooks():
    HostileMessage.touched = False

    assert _handle_with_message(HostileMessage()) is False
    assert HostileMessage.touched is False


def test_list_subclass_message_is_rejected_without_len_or_repr_hooks():
    HostileList.touched = False
    message = HostileList(["done"])

    assert _is_parent_result_message(message) is False
    assert _handle_with_message(message) is False
    assert HostileList.touched is False


def test_exact_list_and_tuple_message_gate_uses_owned_len_only():
    assert _is_parent_result_message(["done"]) is True
    assert _is_parent_result_message(("done",)) is True
    assert _is_parent_result_message([]) is False
    assert _is_parent_result_message(()) is False


def test_malformed_log_message_uses_type_name_without_repr():
    HostileMessage.touched = False

    text = _malformed_parent_result_log_message(HostileMessage())

    assert "HostileMessage" in text
    assert HostileMessage.touched is False


def test_stage1862_removed_parent_result_routes_stay_removed():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/inmemory_parent_result.py"))

    assert "except _queue.Empty:\n        return False" not in source
    assert "except recoverable_exceptions as exc:\n        record_parent_worker_message_failure" in source
    assert "log_error(f'in-memory scheduler ignored malformed result message:" not in source
    assert "msg!r" not in source
    assert "isinstance(msg," not in source
    assert "len(msg)" not in source
