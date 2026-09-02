from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.runtime import loop_guard, loop_guard_contracts, loop_guard_evidence, loop_guard_values
from Virus_Scan.scheduler.runtime.loop_guard import (
    SchedulerLoopGuard,
    SchedulerLoopGuardAdvanceRequest,
    SchedulerLoopGuardState,
    advance_scheduler_loop_guard,
)
from Virus_Scan.scheduler.runtime.loop_guard_values import guard_float, guard_int, guard_text


class HostileScalar:
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def __bool__(self):  # pragma: no cover - failure path
        type(self).touched.append("bool")
        raise AssertionError("__bool__ must not be called")

    def __int__(self):  # pragma: no cover - failure path
        type(self).touched.append("int")
        raise AssertionError("__int__ must not be called")

    def __float__(self):  # pragma: no cover - failure path
        type(self).touched.append("float")
        raise AssertionError("__float__ must not be called")

    def __format__(self, spec):  # pragma: no cover - failure path
        type(self).touched.append("format")
        raise AssertionError("__format__ must not be called")

    def __str__(self):  # pragma: no cover - failure path
        type(self).touched.append("str")
        raise AssertionError("__str__ must not be called")

    def __repr__(self):  # pragma: no cover - failure path
        type(self).touched.append("repr")
        raise AssertionError("__repr__ must not be called")


def test_stage1935_loop_guard_value_helpers_reject_hostile_fields_without_hooks() -> None:
    HostileScalar.reset()
    hostile = HostileScalar()

    text, text_evidence = guard_text(hostile, field_name=hostile, default_value="safe")
    parsed_int, int_evidence = guard_int(hostile, field_name=hostile, default_value=7)
    parsed_float, float_evidence = guard_float(hostile, field_name=hostile, default_value=2.5)

    assert text == "safe"
    assert parsed_int == 7
    assert parsed_float == 2.5
    assert text_evidence and int_evidence and float_evidence
    assert HostileScalar.touched == []


def test_stage1935_loop_guard_contracts_and_advance_reject_hostile_inputs_without_hooks() -> None:
    HostileScalar.reset()
    hostile = HostileScalar()

    guard = SchedulerLoopGuard(hostile, hostile, hostile, hostile, hostile)
    state = SchedulerLoopGuardState.start(now=hostile, progress_total=hostile)
    decision = advance_scheduler_loop_guard(SchedulerLoopGuardAdvanceRequest(
        guard,
        state,
        now=hostile,
        progress_total=hostile,
        pending_count=hostile,
        active_count=hostile,
        completed_count=hostile,
        failed_count=hostile,
        worker_live_count=hostile,
        queue_live_count=hostile,
    ))

    assert decision.exhausted is True
    assert decision.reason == "scheduler_loop_guard_input_rejected"
    assert decision.evidence is not None
    assert decision.evidence["message"] == "scheduler_loop exhausted deterministic guard"
    assert HostileScalar.touched == []


def test_stage1935_loop_guard_source_closes_fallback_and_fstring_rows() -> None:
    source_by_module = {
        "loop_guard": Path(loop_guard.__file__).read_text(encoding="utf-8"),
        "loop_guard_contracts": Path(loop_guard_contracts.__file__).read_text(encoding="utf-8"),
        "loop_guard_values": Path(loop_guard_values.__file__).read_text(encoding="utf-8"),
        "loop_guard_evidence": Path(loop_guard_evidence.__file__).read_text(encoding="utf-8"),
    }
    for module_name, source in source_by_module.items():
        assert "fallback" not in source, module_name
        assert 'f"' not in source, module_name
    assert "message=guard.loop_name +" in source_by_module["loop_guard_evidence"]
