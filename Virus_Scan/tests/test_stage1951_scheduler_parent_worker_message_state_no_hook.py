"""Stage1951 scheduler parent worker message/state no-hook closure."""
from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

import pytest

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.workers.inmemory_parent_message_evidence import record_parent_worker_message_failure
from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import InMemoryLifecycleRecordRequest
from Virus_Scan.scheduler.workers.inmemory_parent_state import (
    mark_worker_assigned_from_message,
    mark_worker_running_from_message,
)
from Virus_Scan.scheduler.workers.inmemory_parent_worker_messages import record_unknown_inmemory_worker_message


class HostileValue:
    touched = 0

    def __str__(self):
        HostileValue.touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        HostileValue.touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        HostileValue.touched += 1
        raise RuntimeError("format hook executed")

    def __int__(self):
        HostileValue.touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):
        HostileValue.touched += 1
        raise RuntimeError("float hook executed")

    def __bool__(self):
        HostileValue.touched += 1
        raise RuntimeError("bool hook executed")

    def __iter__(self):
        HostileValue.touched += 1
        raise RuntimeError("iter hook executed")


class HostileMessage:
    touched = 0

    def __len__(self):
        HostileMessage.touched += 1
        raise RuntimeError("len hook executed")

    def __getitem__(self, _index):
        HostileMessage.touched += 1
        raise RuntimeError("getitem hook executed")

    def __repr__(self):
        HostileMessage.touched += 1
        raise RuntimeError("repr hook executed")

    def __iter__(self):
        HostileMessage.touched += 1
        raise RuntimeError("iter hook executed")


class HostileException(Exception):
    touched = 0

    def __str__(self):
        HostileException.touched += 1
        raise RuntimeError("exception str hook executed")

    def __repr__(self):
        HostileException.touched += 1
        raise RuntimeError("exception repr hook executed")


class HostileRecord(dict):
    touched = 0

    def get(self, *_args, **_kwargs):
        HostileRecord.touched += 1
        raise RuntimeError("record get hook executed")

    def __getitem__(self, _key):
        HostileRecord.touched += 1
        raise RuntimeError("record getitem hook executed")


class HostileTerminal:
    touched = 0

    def __contains__(self, _value):
        HostileTerminal.touched += 1
        raise RuntimeError("terminal contains hook executed")


def _where_values() -> tuple[str, ...]:
    return tuple(record.get("where", "") for record in failure_snapshot().get("records", ()))


def _record_lifecycle(events: list[tuple[int, int, str]], request: InMemoryLifecycleRecordRequest) -> None:
    events.append((request.job_id, request.attempt, request.transition))


def _mark_retry(record: dict[str, object], *, attempt: int, now: float) -> None:
    record["retry_attempt"] = attempt
    record["retry_now"] = now


def test_stage1951_parent_message_failure_materializes_identity_without_hooks():
    clear_failure_records()
    HostileValue.touched = 0
    HostileException.touched = 0

    record_parent_worker_message_failure(
        operation=HostileValue(),
        message=(HostileValue(), HostileValue()),
        exc=HostileException("hidden"),
    )

    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert "inmemory_parent_worker_message_worker_message_failed" in _where_values()


def test_stage1951_unknown_worker_message_identity_avoids_len_getitem_and_repr_hooks():
    clear_failure_records()
    HostileMessage.touched = 0

    result = record_unknown_inmemory_worker_message(HostileMessage())

    assert result.handled is False
    assert result.should_continue is False
    assert HostileMessage.touched == 0
    assert "inmemory_parent_worker_message_unknown_kind_failed" in _where_values()


def test_stage1951_parent_state_rejects_unsupported_message_without_hooks():
    HostileMessage.touched = 0

    with pytest.raises(ValueError, match="unsupported worker state message type"):
        mark_worker_assigned_from_message(
            message=HostileMessage(),
            job_records={},
            active={},
            terminal=set(),
            mark_retry_admitted=_mark_retry,
            lifecycle_recorder=lambda _request: None,
            state_index=InMemorySchedulerStateIndex(),
        )

    assert HostileMessage.touched == 0


def test_stage1951_parent_state_rejects_hostile_numeric_fields_without_conversion_hooks():
    HostileValue.touched = 0

    with pytest.raises(ValueError, match="job_id rejected"):
        mark_worker_running_from_message(
            message=("running", HostileValue(), "file.py", HostileValue(), HostileValue(), HostileValue(), HostileValue()),
            job_records={},
            active={},
            terminal=set(),
            worker_heartbeats={},
            mark_retry_admitted=_mark_retry,
            lifecycle_recorder=lambda _request: None,
            state_index=InMemorySchedulerStateIndex(),
        )

    assert HostileValue.touched == 0


def test_stage1951_parent_state_rejects_non_owned_record_and_terminal_without_hooks():
    HostileRecord.touched = 0
    HostileTerminal.touched = 0
    active: dict[int, dict[str, object]] = {}
    events: list[tuple[int, int, str]] = []

    result = mark_worker_assigned_from_message(
        message=("assigned", 7, "game.py", 101, 5.0, 1, 0),
        job_records={7: HostileRecord({"attempt": 1})},
        active=active,
        terminal=HostileTerminal(),
        mark_retry_admitted=_mark_retry,
        lifecycle_recorder=lambda request: _record_lifecycle(events, request),
        state_index=InMemorySchedulerStateIndex(),
    )

    assert result is False
    assert active == {}
    assert events == []
    assert HostileRecord.touched == 0
    assert HostileTerminal.touched == 0


def test_stage1951_parent_state_exact_dict_messages_preserve_assigned_and_running_behavior():
    active: dict[int, dict[str, object]] = {}
    heartbeats: dict[int, float] = {}
    events: list[tuple[int, int, str]] = []
    records: dict[int, dict[str, object]] = {7: {"attempt": 2}}
    state_index = InMemorySchedulerStateIndex()

    assigned = mark_worker_assigned_from_message(
        message=("assigned", 7, "game.py", 101, 5.0, 2, 0),
        job_records=records,
        active=active,
        terminal=set(),
        mark_retry_admitted=_mark_retry,
        lifecycle_recorder=lambda request: _record_lifecycle(events, request),
        state_index=state_index,
    )
    running = mark_worker_running_from_message(
        message=("running", 7, "game.py", 101, 6.0, 2, 9),
        job_records=records,
        active=active,
        terminal=set(),
        worker_heartbeats=heartbeats,
        mark_retry_admitted=_mark_retry,
        lifecycle_recorder=lambda request: _record_lifecycle(events, request),
        state_index=state_index,
    )

    assert assigned is True
    assert running is True
    assert records[7]["state"] == "running"
    assert records[7]["thread_id"] == 9
    assert active[7]["assigned"] == 5.0
    assert active[7]["attempt"] == 2
    assert heartbeats == {101: 6.0}
    assert events == [(7, 2, "assigned"), (7, 2, "running")]
