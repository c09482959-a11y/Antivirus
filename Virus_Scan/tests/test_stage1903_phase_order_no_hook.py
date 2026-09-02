from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.phase_order import queue_phase_order, validate_queue_phase_transition


class HostilePhase:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


def test_stage1903_queue_phase_order_rejects_hostile_phase_without_hooks() -> None:
    HostilePhase.touched = 0

    with pytest.raises(RuntimeError, match="unknown scheduler queue phase"):
        queue_phase_order(HostilePhase())

    assert HostilePhase.touched == 0


def test_stage1903_queue_phase_transition_rejects_hostile_inputs_without_hooks() -> None:
    HostilePhase.touched = 0

    with pytest.raises(RuntimeError, match="unknown scheduler queue phase"):
        validate_queue_phase_transition(HostilePhase(), "finalize")

    assert HostilePhase.touched == 0


def test_stage1903_phase_order_source_has_no_raw_str_bool_or_fstring_routes() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/phase_order.py"))

    assert 'str(phase or "unknown")' not in source
    assert 'str(previous_phase or "unknown")' not in source
    assert 'str(current_phase or "unknown")' not in source
    assert 'f"unknown scheduler queue phase: {phase_name}"' not in source
    assert 'f"scheduler queue phase regression: {previous} -> {current}"' not in source
    assert "_queue_phase_order = queue_phase_order" not in source
    assert "_validate_queue_phase_transition = validate_queue_phase_transition" not in source
