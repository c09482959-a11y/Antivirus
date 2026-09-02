from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.raw_integrity import (
    apply_integrity_tags,
    mark_raw_integrity_failure,
    raw_integrity_degraded,
)
from Virus_Scan.scheduler.queue.raw_queue_accumulator import RawAccumulatorDependencies, RawAccumulatorStore


class HostileRawQueueValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("raw queue called __bool__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue called __iter__")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue called __len__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue called __format__")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue called __int__")


class HostileRawQueueException(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue exception called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue exception called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue exception called __format__")


class HostileRawQueueMapping:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue mapping called __bool__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue mapping called __iter__")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue mapping called items")

    def get(self, *_args, **_kwargs):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue mapping called get")


class HostileFileId:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue file id called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue file id called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue file id called __format__")


def _reset() -> None:
    HostileRawQueueValue.touched = 0
    HostileRawQueueException.touched = 0
    HostileRawQueueMapping.touched = 0
    HostileFileId.touched = 0


def _deps(root: Path, *, write_ok: bool = True) -> RawAccumulatorDependencies:
    dirs = tuple(root / name for name in ("pending", "active", "done", "failed", "accumulators", "locks"))
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
    return RawAccumulatorDependencies(
        global_raw_dirs=lambda _queue_dir: dirs,
        read_json_file=lambda *_args, **_kwargs: {},
        write_json_durable=lambda *_args, **_kwargs: write_ok,
        ordered_unique_tags=lambda tags: list(dict.fromkeys(tags)),
        normalize_yara_hits=lambda hits: list(hits),
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(RuntimeError,),
    )


def test_stage1913_raw_integrity_degraded_rejects_unknown_snapshot_without_hooks() -> None:
    _reset()

    assert raw_integrity_degraded(HostileRawQueueMapping()) is True
    assert raw_integrity_degraded({"raw_failed": HostileRawQueueValue()}) is True
    assert raw_integrity_degraded({"raw_failed": 0, "raw_failures": []}) is False
    assert HostileRawQueueMapping.touched == 0
    assert HostileRawQueueValue.touched == 0


def test_stage1913_apply_integrity_tags_does_not_iterate_hostile_tags() -> None:
    _reset()

    tags = apply_integrity_tags(
        HostileRawQueueValue(),
        {"raw_failed": 1},
        marker="raw_accumulator_incomplete",
        scanner_degraded_tags=lambda values: values + ["scanner_degraded"],
    )

    assert tags == ["raw_accumulator_incomplete", "scanner_degraded"]
    assert HostileRawQueueValue.touched == 0


def test_stage1913_mark_raw_integrity_failure_rejects_hostile_fields_and_exception_without_hooks(tmp_path: Path) -> None:
    _reset()
    reports: list[str] = []
    stored: list[dict[str, object]] = []
    exc = HostileRawQueueException(HostileRawQueueValue())

    info = mark_raw_integrity_failure(
        tmp_path / "sample.bin",
        {"raw_failed": HostileRawQueueValue()},
        marker=HostileRawQueueValue(),
        where=HostileRawQueueValue(),
        exc=exc,
        set_scan_integrity=lambda _path, value: stored.append(value),
        report=lambda where, _exc: reports.append(where),
        recoverable_exceptions=(RuntimeError,),
    )

    assert info["raw_failed"] == 1
    assert info["stage120_marker"] == "raw_queue"
    assert info["failure_info"]["stage"] == "raw_queue"
    assert info["failure_info"]["error"] == "raw_integrity_exception_unavailable"
    assert reports == ["raw_queue"]
    assert stored == [info]
    assert HostileRawQueueValue.touched == 0
    assert HostileRawQueueException.touched == 0


def test_stage1913_raw_accumulator_store_save_and_complete_reject_hooks(tmp_path: Path) -> None:
    _reset()
    deps = _deps(tmp_path, write_ok=False)
    store = RawAccumulatorStore(tmp_path, HostileFileId(), deps)

    assert store.file_id == "raw_accumulator_file_id_unavailable"
    assert RawAccumulatorStore.is_complete(HostileRawQueueMapping(), deps) is False
    with pytest.raises(RuntimeError, match="raw accumulator save failed"):
        store.save({"expected": HostileRawQueueValue(), "completed": HostileRawQueueValue()})
    assert HostileFileId.touched == 0
    assert HostileRawQueueMapping.touched == 0
    assert HostileRawQueueValue.touched == 0


def test_stage1913_raw_integrity_accumulator_source_guards() -> None:
    integrity_source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_integrity.py"))
    accumulator_source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_accumulator.py"))

    assert "except (AttributeError, TypeError):\n        return True" not in integrity_source
    assert "bool(" not in integrity_source
    assert "dict(integrity)" not in integrity_source
    assert "int(0 if failed_count is None else failed_count)" not in integrity_source
    assert "str(exc)" not in integrity_source
    assert 'f".{os.getpid()}.tmp"' not in accumulator_source
    assert 'f"raw accumulator save failed: {self.path}"' not in accumulator_source
    assert 'int(data.get("expected", 0) or 0)' not in accumulator_source
    assert 'int(expected or 0)' not in accumulator_source
    assert "except (AttributeError, TypeError, ValueError):\n            return False" not in accumulator_source
