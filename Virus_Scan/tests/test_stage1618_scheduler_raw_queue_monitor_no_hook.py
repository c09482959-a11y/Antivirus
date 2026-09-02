from __future__ import annotations

from Virus_Scan.scheduler.evidence.raw_queue_monitor import (
    queue_io_pressure_sample,
    queue_pressure_flags,
    queue_progress_counts_global,
)
from Virus_Scan.scheduler.runtime.env_policy import bool_env, float_env, int_env, scheduler_environment_snapshot


class HostileSchedulerValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not format")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath")


class HostileMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool mapping")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate mapping")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get mapping")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items mapping")


class HostileDiskCounters:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @property
    def busy_time(self):
        type(self).touched += 1
        raise RuntimeError("do not read busy_time")


class FakePsutil:
    def __init__(self):
        self.calls = 0

    def disk_io_counters(self):
        self.calls += 1
        return HostileDiskCounters()


def _reset() -> None:
    HostileSchedulerValue.reset()
    HostileMapping.reset()
    HostileDiskCounters.reset()


def test_stage1618_queue_pressure_flags_rejects_hostile_mapping_without_hooks() -> None:
    _reset()

    sample = queue_pressure_flags(HostileMapping())

    assert HostileMapping.touched == 0
    assert sample["pressure"] is False
    assert sample["reason"] == "unsupported_queue_pressure_sample"
    assert sample["evidence"]["unsupported_scheduler_value"] is True


def test_stage1618_queue_progress_counts_rejects_hostile_job_name_without_hooks(tmp_path) -> None:
    _reset()
    reports = []
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    for directory in (pending, active, done, failed):
        directory.mkdir()

    counts = queue_progress_counts_global(
        tmp_path,
        ensure_dirs=lambda _: None,
        queue_job_dirs=lambda _: (pending, active, done, failed),
        safe_queue_listdir=lambda directory: [HostileSchedulerValue()] if directory == pending else [],
        is_job_json_name=lambda name: (_ for _ in ()).throw(AssertionError("hostile name reached json check")),
        read_json_file=lambda *args, **kwargs: {},
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
    )

    assert HostileSchedulerValue.touched == 0
    assert counts == {
        "file_pending": 0,
        "file_active": 0,
        "file_done": 0,
        "file_failed": 0,
        "raw_pending": 0,
        "raw_active": 0,
        "raw_done": 0,
        "raw_failed": 0,
    }
    assert any(args[0] == "queue_progress_job_name_rejected" for args, _ in reports)


def test_stage1618_environment_snapshot_rejects_hostile_mapping_without_iteration_or_get() -> None:
    _reset()

    snapshot = scheduler_environment_snapshot(HostileMapping())

    assert HostileMapping.touched == 0
    assert snapshot.get("scheduler_mapping_unavailable") is True


def test_stage1618_io_pressure_rejects_hostile_queue_dir_env_and_disk_properties(tmp_path) -> None:
    _reset()
    reports = []
    psutil = FakePsutil()

    sample = queue_io_pressure_sample(
        HostileSchedulerValue(),
        safe_queue_listdir=lambda path: [],
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
        psutil_module=psutil,
        environ=HostileMapping(),
        sleep=lambda seconds: None,
        time_fn=lambda: 1.0,
    )

    assert HostileSchedulerValue.touched == 0
    assert HostileMapping.touched == 0
    assert HostileDiskCounters.touched == 0
    assert sample["pressure"] is False
    assert any(args[0] == "io_pressure_queue_dir_rejected" for args, _ in reports)
    assert any(args[0] == "io_pressure_psutil_probe_failed" for args, _ in reports)


def test_stage1618_env_policy_parsers_reject_hostile_mapping_without_hooks() -> None:
    _reset()

    assert float_env(HostileMapping(), "VALUE", 2.5, (Exception,)) == 2.5
    assert int_env(HostileMapping(), "VALUE", 7, (Exception,)) == 7
    assert bool_env(HostileMapping(), "VALUE", True, (Exception,)) is True

    assert HostileMapping.touched == 0
