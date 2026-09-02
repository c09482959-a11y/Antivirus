"""Stage2132 in-memory raw policy typed boundary regressions."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.context import inmemory_raw_policy_dependencies as policy
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileExtra:
    str_calls = 0
    repr_calls = 0
    iter_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.iter_calls = 0

    @classmethod
    def counters(cls) -> dict[str, int]:
        return {"str": cls.str_calls, "repr": cls.repr_calls, "iter": cls.iter_calls}

    def __str__(self):  # pragma: no cover - execution is failure
        type(self).str_calls += 1
        raise AssertionError("hostile __str__ executed")

    def __repr__(self):  # pragma: no cover
        type(self).repr_calls += 1
        raise AssertionError("hostile __repr__ executed")

    def __iter__(self):  # pragma: no cover
        type(self).iter_calls += 1
        raise AssertionError("hostile __iter__ executed")


def test_stage2132_raw_policy_dependency_surface_has_no_any_annotations() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/context/inmemory_raw_policy_dependencies.py"))
    assert "typing import Any" not in source
    assert ": Any" not in source
    assert "-> Any" not in source


def test_stage2132_raw_queue_issue_rejects_non_mapping_extra_without_hooks() -> None:
    HostileExtra.reset()
    captured: list[tuple[str, dict[str, object] | None]] = []

    def record_scheduler_suppressed(stage: str, exc: BaseException, *, extra: dict[str, object] | None = None) -> None:
        captured.append((stage, extra))

    original_recorder = policy.record_scheduler_suppressed
    policy.record_scheduler_suppressed = record_scheduler_suppressed
    try:
        policy.record_raw_queue_issue("stage2132", RuntimeError("boom"), extra=HostileExtra())
    finally:
        policy.record_scheduler_suppressed = original_recorder

    assert HostileExtra.counters() == {"str": 0, "repr": 0, "iter": 0}
    assert captured
    extra = captured[0][1]
    assert extra is not None
    assert extra["raw_queue_issue_extra_rejected"] is True
    assert extra["extra_type"] == "HostileExtra"
