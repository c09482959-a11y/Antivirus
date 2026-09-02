from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path


import pytest

from Virus_Scan.scheduler.queue.raw_accumulator_lock import GlobalRawAccumLock
from Virus_Scan.scheduler.queue.raw_accumulator_store import raw_accumulator_dependencies


class HostileValue:
    touched = 0

    def __getattribute__(self, name):  # pragma: no cover - executed only on regression
        type(self).touched += 1
        raise AssertionError("caller-owned attribute hook executed")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned str hook executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned format hook executed")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned fspath hook executed")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned float hook executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned bool hook executed")


def _reset() -> None:
    HostileValue.touched = 0


def test_raw_accumulator_lock_rejects_hostile_timeout_without_float_hook(tmp_path):
    _reset()
    with pytest.raises(TypeError) as excinfo:
        GlobalRawAccumLock(tmp_path, "stage1911", timeout=HostileValue(), deps=raw_accumulator_dependencies())
    assert str(excinfo.value) == "raw accumulator lock timeout rejected: raw_accumulator_lock_timeout_rejected"
    assert HostileValue.touched == 0


def test_raw_accumulator_lock_rejects_hostile_name_without_text_or_format_hooks(tmp_path):
    _reset()
    with pytest.raises(TypeError) as excinfo:
        GlobalRawAccumLock(tmp_path, HostileValue(), deps=raw_accumulator_dependencies())
    assert str(excinfo.value) == "raw accumulator lock name rejected: raw_accumulator_lock_name_rejected"
    assert HostileValue.touched == 0


def test_raw_accumulator_lock_accepts_owned_dependency_and_uses_owned_path_text(tmp_path):
    deps = raw_accumulator_dependencies()
    lock = GlobalRawAccumLock(tmp_path, "stage1911", timeout=0.01, deps=deps)
    with lock:
        assert lock.path.exists()
    assert not lock.path.exists()


def test_stage1911_source_guard_removed_raw_accumulator_lock_helper_fallback_and_fspath_boundaries():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_accumulator_lock.py"))
    forbidden = (
        "safe_scheduler_instance_callable",
        "safe_scheduler_bound_method",
        "replacement_text=\"\"",
        "default=30.0",
        "os.fspath",
        "typing_extensions",
    )
    for pattern in forbidden:
        assert pattern not in source
    assert "from typing import Self" in source
