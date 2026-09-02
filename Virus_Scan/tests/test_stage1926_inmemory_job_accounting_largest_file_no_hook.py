from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex


class HostileNumber:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile bool hook touched")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile int hook touched")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile float hook touched")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile str hook touched")


def test_stage1926_hostile_heavy_weight_is_ignored_without_numeric_or_truthiness_hooks() -> None:
    HostileNumber.touched = 0
    index = InMemorySchedulerStateIndex()

    index.sync_record(
        1,
        {"state": "running", "file": "sample.bin", "cost": {"heavy": True, "weight": HostileNumber()}},
        due_at=1.0,
    )

    assert index.logical_inflight_count() == 1
    assert index.active_heavy_weight() == 0
    assert HostileNumber.touched == 0


def test_stage1926_state_index_source_has_no_whole_registry_accounting_scan() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "Virus_Scan/scheduler/ownership/inmemory_scheduler_state_index.py").read_text(encoding="utf-8")

    assert "job_records" not in source
    assert ".values()" not in source
    assert ".items()" not in source
    assert "tuple(dict.items" not in source
    assert "fallback" not in source
