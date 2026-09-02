from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.runtime import backpressure_memory, backpressure_targets
from Virus_Scan.scheduler.runtime.backpressure_memory import cpu_count_safe, memory_pressure_level
from Virus_Scan.scheduler.runtime.backpressure_targets import (
    dynamic_process_queue_target,
    elastic_target_workers,
    io_adjusted_elastic_target,
    smooth_worker_target,
)


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

    def __str__(self):  # pragma: no cover - failure path
        type(self).touched.append("str")
        raise AssertionError("__str__ must not be called")

    def __repr__(self):  # pragma: no cover - failure path
        type(self).touched.append("repr")
        raise AssertionError("__repr__ must not be called")


class HostileSnapshot(dict):
    touched: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.touched = []

    def get(self, key, default=None):  # pragma: no cover - failure path
        type(self).touched.append("get")
        raise AssertionError("mapping get must not be called")

    def __bool__(self):  # pragma: no cover - failure path
        type(self).touched.append("bool")
        raise AssertionError("mapping bool must not be called")

    def __iter__(self):  # pragma: no cover - failure path
        type(self).touched.append("iter")
        raise AssertionError("mapping iter must not be called")


def test_stage1933_backpressure_memory_rejects_hostile_snapshot_without_hooks() -> None:
    HostileSnapshot.reset()

    assert memory_pressure_level(HostileSnapshot({"pressure": "critical"})) == "unknown"

    assert HostileSnapshot.touched == []


def test_stage1933_backpressure_targets_reject_hostile_scalars_without_hooks() -> None:
    HostileScalar.reset()
    hostile = HostileScalar()

    assert cpu_count_safe(hostile) >= 1
    assert elastic_target_workers(hostile, hostile, raw_live=hostile, max_workers=hostile) >= 1
    assert smooth_worker_target(hostile, hostile) >= 1
    io_target, _cpu, _io_sample = io_adjusted_elastic_target(hostile, hostile)
    dynamic_target, _cpu_dynamic = dynamic_process_queue_target(hostile, hostile)

    assert io_target >= 1
    assert dynamic_target >= 1
    assert HostileScalar.touched == []


def test_stage1933_backpressure_source_closes_known_hook_rows() -> None:
    memory_source = Path(backpressure_memory.__file__).read_text(encoding="utf-8")
    target_source = Path(backpressure_targets.__file__).read_text(encoding="utf-8")

    forbidden_memory = (
        "return int(default or 4)",
        'float(getattr(vm, "available", 0) or 0)',
        'float(getattr(vm, "percent", 0.0) or 0.0)',
        'str((snap or {}).get("pressure") or "unknown")',
        'return "unknown"',
    )
    forbidden_targets = (
        "int(max_workers or 100)",
        "int(raw_live or 0)",
        "int(target or 1)",
        "int(prev or 1)",
        "return None",
        "int(process_count or requested_process_count or 1)",
    )
    for snippet in forbidden_memory:
        assert snippet not in memory_source
    for snippet in forbidden_targets:
        assert snippet not in target_source
