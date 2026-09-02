from __future__ import annotations

from pathlib import Path
from typing import Iterator

from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.scheduler.timeout.process_queue_stall_reporting import (
    pid_for_process,
    termination_result_snapshot,
)


class HostileMissingTermination:
    def __init__(self) -> None:
        self.calls: list[str] = []

    @property
    def pid(self):
        self.calls.append("pid")
        raise AssertionError("pid property must not run")

    @property
    def error(self):
        self.calls.append("error")
        raise AssertionError("error property must not run")

    def __iter__(self) -> Iterator[object]:
        self.calls.append("iter")
        raise AssertionError("iter must not run")

    def __repr__(self):
        self.calls.append("repr")
        raise AssertionError("repr must not run")

    def __str__(self):
        self.calls.append("str")
        raise AssertionError("str must not run")


class ProcWithNonePid:
    pid = None


def test_stage2136_unsupported_public_termination_result_is_replayable_without_hooks() -> None:
    hostile = HostileMissingTermination()
    replacement_pid = pid_for_process(ProcWithNonePid())

    snapshot = termination_result_snapshot(hostile, replacement_pid=replacement_pid)

    assert hostile.calls == []
    assert snapshot["supported"] is False
    assert snapshot["pid"] == replacement_pid
    assert snapshot["error"] == "unsupported_termination_result"
    assert snapshot["unavailable_reason"] == "public_termination_fields_unavailable"
    evidence = snapshot["evidence"]
    assert type(evidence) is dict
    assert evidence["unsupported_scheduler_value"] is True


def test_stage2136_process_queue_stall_reporting_source_removes_any_and_optional_sentinels() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/timeout/process_queue_stall_reporting.py"))

    assert "from typing import Any" not in source
    assert ": Any" not in source
    assert "tuple[Any" not in source
    assert "dict[str, Any" not in source
    assert "return None" not in source
    assert "PublicTerminationSnapshotDecision" in source
