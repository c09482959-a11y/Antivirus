from __future__ import annotations

import inspect

from Virus_Scan.scheduler.ownership import inmemory_live_state, inmemory_live_state_materialization
from Virus_Scan.scheduler.ownership.inmemory_live_state import InMemoryLiveSchedulerState


class HostileLiveScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("format hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")


class HostileLiveContainer:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("iter hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")


def _outcomes_by_field(state: InMemoryLiveSchedulerState):
    return {outcome.field: outcome for outcome in state.constructor_outcomes}


def test_stage2095_default_live_state_inputs_are_replayable_typed_outcomes() -> None:
    state = InMemoryLiveSchedulerState(active=None, processes=None, ewma_state=None)

    outcomes = _outcomes_by_field(state)

    assert state.constructor_rejections == ()
    assert outcomes["active"].status == "defaulted"
    assert outcomes["active"].reason == "inmemory_live_mapping_missing"
    assert outcomes["processes"].status == "defaulted"
    assert outcomes["processes"].reason == "inmemory_live_processes_missing"
    assert outcomes["ewma_state"].status == "defaulted"
    assert outcomes["ewma_state"].reason == "inmemory_live_ewma_missing"


def test_stage2095_rejected_live_state_inputs_record_typed_replayable_outcomes_without_hooks() -> None:
    HostileLiveScalar.reset()
    HostileLiveContainer.reset()
    hostile_key = HostileLiveScalar()
    hostile_done = HostileLiveScalar()
    hostile_processes = HostileLiveContainer()

    state = InMemoryLiveSchedulerState(
        active={hostile_key: "unsafe"},
        done=(hostile_done,),
        processes=hostile_processes,
    )

    outcomes = _outcomes_by_field(state)
    fields = {entry["field"] for entry in state.constructor_rejections}

    assert HostileLiveScalar.touched == 0
    assert HostileLiveContainer.touched == 0
    assert state.active == {}
    assert state.done == set()
    assert state.processes == []
    assert "active_key_0" in fields
    assert "done_0" in fields
    assert "processes" in fields
    assert outcomes["active"].status == "materialized"
    assert outcomes["active"].rejection_count == 1
    assert outcomes["done"].status == "materialized"
    assert outcomes["done"].rejection_count == 1
    assert outcomes["processes"].status == "rejected"
    assert outcomes["processes"].reason == "inmemory_live_processes_rejected"


def test_stage2095_live_state_source_removed_tracked_default_return_helpers() -> None:
    public_source = inspect.getsource(inmemory_live_state)
    materialization_source = inspect.getsource(inmemory_live_state_materialization)
    combined = public_source + materialization_source

    assert "def _safe_mapping_key" not in combined
    assert "def _safe_set_item" not in combined
    assert "def _copy_live_mapping" not in combined
    assert "def _copy_live_set" not in combined
    assert "def _copy_live_processes" not in combined
    assert "def _copy_ewma_state" not in combined
    assert "return None" not in combined
    assert "return {}" not in combined
    assert "return []" not in combined
    assert "return set()" not in combined
