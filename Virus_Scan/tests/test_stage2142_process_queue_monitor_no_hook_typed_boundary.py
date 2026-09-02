from __future__ import annotations

import inspect

from Virus_Scan.scheduler.orchestration import process_queue_monitor_no_hook as monitor


class HostileMonitorKey:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __hash__(self) -> int:
        return 42

    def __eq__(self, _other: object) -> bool:
        type(self).touched += 1
        raise RuntimeError("hostile monitor key equality executed")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("hostile monitor key string conversion executed")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("hostile monitor key repr executed")


class HostileMonitorValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("hostile monitor value bool executed")

    def __int__(self) -> int:
        type(self).touched += 1
        raise RuntimeError("hostile monitor value int executed")

    def __float__(self) -> float:
        type(self).touched += 1
        raise RuntimeError("hostile monitor value float executed")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("hostile monitor value str executed")


class HostileMappingLike:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __getattribute__(self, name: str) -> object:
        if name not in {"touched", "reset", "__class__"}:
            type(self).touched += 1
            raise RuntimeError("hostile monitor mapping inspection executed")
        return object.__getattribute__(self, name)

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("hostile monitor mapping iteration executed")

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("hostile monitor mapping bool executed")


def setup_function(_func: object) -> None:
    HostileMonitorKey.reset()
    HostileMonitorValue.reset()
    HostileMappingLike.reset()


def test_stage2142_monitor_no_hook_source_has_typed_decision_boundary() -> None:
    source = inspect.getsource(monitor)

    assert "from typing import Any" not in source
    assert ": Any" not in source
    assert "-> Any" not in source
    assert "tuple[Any" not in source
    assert "return None" not in source
    assert "_monitor_mapping_items" not in source
    assert "MonitorMappingDecision" in source
    assert "MonitorPressureDecision" in source


def test_stage2142_monitor_pressure_ignores_hostile_keys_without_equality() -> None:
    pressure = monitor.monitor_elastic_io_pressure({HostileMonitorKey(): True, "pressure": True})

    assert pressure is True
    assert HostileMonitorKey.touched == 0


def test_stage2142_monitor_feed_counts_rejects_hostile_keys_and_values_without_hooks() -> None:
    hostile_value = HostileMonitorValue()
    done, failed, active, pending, raw_live, counts = monitor.monitor_feed_counts(
        {HostileMonitorKey(): hostile_value, "file_done": hostile_value, "raw_pending": hostile_value},
        file_done_count=3,
        file_failed_count=4,
        file_active_count=5,
        file_pending_count=6,
        raw_live=7,
        default_counts={"fallback": True},
    )

    assert HostileMonitorKey.touched == 0
    assert HostileMonitorValue.touched == 0
    assert (done, failed, active, pending, raw_live) == (3, 4, 5, 6, 0)
    assert counts["file_done"]["unsupported_scheduler_value"] is True


def test_stage2142_monitor_mapping_decision_records_unavailable_evidence_without_hooks() -> None:
    hostile_mapping = HostileMappingLike()

    sample = monitor.monitor_elastic_io_sample(hostile_mapping)
    done, failed, active, pending, raw_live, counts = monitor.monitor_feed_counts(
        hostile_mapping,
        file_done_count=1,
        file_failed_count=2,
        file_active_count=3,
        file_pending_count=4,
        raw_live=5,
        default_counts={"safe": "default"},
    )

    assert HostileMappingLike.touched == 0
    assert sample["scheduler_monitor_elastic_io_sample_unavailable"] is True
    assert sample["reason"] == "process_queue_monitor_elastic_io_sample_rejected"
    assert (done, failed, active, pending, raw_live) == (1, 2, 3, 4, 5)
    assert counts["scheduler_monitor_feed_counts_unavailable"] is True
    assert counts["reason"] == "process_queue_monitor_feed_counts_rejected"
