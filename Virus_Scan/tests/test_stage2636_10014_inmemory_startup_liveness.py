from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.orchestration.inmemory_parent_loop_guard import (
    startup_recovery_decision,
)


class _Process:
    def __init__(self, pid: int, alive: bool) -> None:
        self.pid = pid
        self._alive = alive

    def is_alive(self) -> bool:
        return self._alive


@dataclass
class _Recovery:
    completed: int


@dataclass
class _Setup:
    recovery: _Recovery
    procs: list[_Process]


def test_slow_live_workers_do_not_trigger_serial_startup_recovery() -> None:
    decision = startup_recovery_decision(
        _Setup(_Recovery(completed=0), [_Process(101, True)]),
        deadline=3.0,
        now=8.0,
    )

    assert decision.required is False
    assert decision.reason == "startup_workers_alive"
    assert decision.live_workers == 1
    assert decision.deadline_expired is True


def test_dead_startup_workers_trigger_explicit_recovery() -> None:
    decision = startup_recovery_decision(
        _Setup(_Recovery(completed=0), [_Process(102, False)]),
        deadline=3.0,
        now=8.0,
    )

    assert decision.required is True
    assert decision.reason == "startup_workers_unavailable"
    assert decision.live_workers == 0


def test_completed_startup_never_reenters_recovery() -> None:
    decision = startup_recovery_decision(
        _Setup(_Recovery(completed=1), [_Process(103, False)]),
        deadline=3.0,
        now=8.0,
    )

    assert decision.required is False
    assert decision.reason == "startup_completion_observed"
    assert decision.completed == 1
