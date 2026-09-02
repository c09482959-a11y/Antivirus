from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from pathlib import Path

from Virus_Scan.scheduler.workers.inmemory_parent_state import (
    _owned_job_record,
    _owned_job_record_decision,
    _record_assigned_at,
    _record_assigned_at_decision,
    _worker_state_application_decision,
    mark_worker_assigned_from_message,
    mark_worker_running_from_message,
)


class HostileRecord(dict):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("dict get hook executed")

    def __getitem__(self, _key):
        type(self).touched += 1
        raise RuntimeError("dict getitem hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("dict bool hook executed")


class HostileTerminal:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __contains__(self, _value):
        type(self).touched += 1
        raise RuntimeError("terminal contains hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("terminal bool hook executed")


def _mark_retry(record: dict[str, object], *, attempt: int, now: float) -> None:
    record["retry_attempt"] = attempt
    record["retry_now"] = now


def test_stage2118_owned_job_record_missing_is_replayable_decision_without_none_return() -> None:
    HostileRecord.reset()
    decision = _owned_job_record_decision({7: HostileRecord({"attempt": 1})}, 7)

    assert decision.accepted is False
    assert decision.record is None
    assert decision.reason == "missing_or_unsupported_job_record"
    assert _owned_job_record({7: HostileRecord({"attempt": 1})}, 7) is None
    assert HostileRecord.touched == 0


def test_stage2118_record_assigned_at_rejection_is_replayable_decision_without_zero_return() -> None:
    decision = _record_assigned_at_decision({"assigned_at": object()})

    assert decision.accepted is False
    assert decision.value == 0.0
    assert decision.reason == "worker_record_assigned_at_rejected"
    assert _record_assigned_at({"assigned_at": object()}) == 0.0


def test_stage2118_parent_state_rejections_have_typed_reasons_without_public_false_literals() -> None:
    missing = _worker_state_application_decision(None, set(), 7, 1)
    assert missing.applied is False
    assert missing.reason == "missing_or_unsupported_job_record"

    terminal = _worker_state_application_decision({"attempt": 1}, {7}, 7, 1)
    assert terminal.applied is False
    assert terminal.reason == "terminal_job_rejected"

    mismatch = _worker_state_application_decision({"attempt": 2}, set(), 7, 1)
    assert mismatch.applied is False
    assert mismatch.reason == "attempt_mismatch"


def test_stage2118_parent_state_public_bool_wrappers_preserve_behavior_without_hooks() -> None:
    HostileRecord.reset()
    HostileTerminal.reset()
    active: dict[int, dict[str, object]] = {}
    events: list[tuple[int, int, str]] = []
    state_index = InMemorySchedulerStateIndex()

    rejected = mark_worker_assigned_from_message(
        message=("assigned", 7, "game.py", 101, 5.0, 1, 0),
        job_records={7: HostileRecord({"attempt": 1})},
        active=active,
        terminal=HostileTerminal(),
        mark_retry_admitted=_mark_retry,
        lifecycle_recorder=lambda request: events.append((request.job_id, request.attempt, request.transition)),
        state_index=state_index,
    )

    assert rejected is False
    assert active == {}
    assert events == []
    assert HostileRecord.touched == 0
    assert HostileTerminal.touched == 0

    records: dict[int, dict[str, object]] = {7: {"attempt": 1, "assigned_at": object()}}
    heartbeats: dict[int, float] = {}
    running = mark_worker_running_from_message(
        message=("running", 7, "game.py", 101, 6.0, 1, 9),
        job_records=records,
        active=active,
        terminal=set(),
        worker_heartbeats=heartbeats,
        mark_retry_admitted=_mark_retry,
        lifecycle_recorder=lambda request: events.append((request.job_id, request.attempt, request.transition)),
        state_index=state_index,
    )

    assert running is True
    assert active[7]["assigned"] == 0.0
    assert heartbeats == {101: 6.0}


def test_stage2118_inmemory_parent_state_source_removed_targeted_hidden_returns() -> None:
    source = Path("Virus_Scan/scheduler/workers/inmemory_parent_state.py").read_text(encoding="utf-8")

    assert "return None" not in source
    assert "return 0.0" not in source
    assert "return False" not in source
    assert "WorkerJobRecordDecision" in source
    assert "WorkerTimestampDecision" in source
    assert "WorkerStateApplyDecision" in source
    assert "typing import Any" not in source
    assert ": Any" not in source
    assert "WorkerRecord: TypeAlias = dict[str, object]" in source
    assert "WorkerStateMessage: TypeAlias" in source
