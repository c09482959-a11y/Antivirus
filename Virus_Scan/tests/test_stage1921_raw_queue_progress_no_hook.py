from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_progress import file_has_recent_raw_owner_progress


class HostileValue:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile bool hook touched")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile str hook touched")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile repr hook touched")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile int hook touched")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile float hook touched")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile fspath hook touched")


class HostileStore:
    def __init__(self, queue_dir, file_id):
        self.path = Path(queue_dir) / (file_id + ".json")

    def load(self):
        return {"file_id": "fid", "expected": HostileValue(), "completed": HostileValue(), "updated_at": HostileValue()}

    @staticmethod
    def is_complete(_data):
        return HostileValue()


def test_stage1921_rejects_hostile_paths_without_bool_or_fspath_hooks() -> None:
    HostileValue.touched = 0
    hostile = HostileValue()

    info = file_has_recent_raw_owner_progress(
        hostile,
        hostile,
        global_raw_file_id=lambda _path: "fid",
        accumulator_store_cls=HostileStore,
        queue_now=lambda: 100.0,
        raw_stage_progress_recent=lambda *_args, **_kwargs: False,
        report=lambda *_args, **_kwargs: None,
    )

    assert info == {"has_accumulator": False, "complete": False, "recent": False, "age": None, "file_id": None}
    assert HostileValue.touched == 0


def test_stage1921_rejects_hostile_progress_scalars_without_numeric_or_bool_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0

    info = file_has_recent_raw_owner_progress(
        tmp_path,
        tmp_path / "sample.bin",
        quiet_sec=HostileValue(),
        global_raw_file_id=lambda _path: "fid",
        accumulator_store_cls=HostileStore,
        queue_now=lambda: HostileValue(),
        raw_stage_progress_recent=lambda *_args, **_kwargs: HostileValue(),
        report=lambda *_args, **_kwargs: None,
    )

    assert info["has_accumulator"] is False
    assert info["recent"] is False
    assert HostileValue.touched == 0


def test_stage1921_reports_failures_with_scheduler_owned_path_evidence(tmp_path: Path) -> None:
    reports = []

    info = file_has_recent_raw_owner_progress(
        tmp_path,
        tmp_path / "sample.bin",
        global_raw_file_id=lambda _path: (_ for _ in ()).throw(RuntimeError("boom")),
        accumulator_store_cls=HostileStore,
        queue_now=lambda: 100.0,
        raw_stage_progress_recent=lambda *_args, **_kwargs: False,
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
    )

    assert info["recent"] is False
    assert reports
    extra = reports[0][1]["extra"]
    assert extra["queue_dir"] == str(tmp_path)
    assert extra["queue_dir_reason"] == ""
    assert extra["file_path"] == str(tmp_path / "sample.bin")
    assert extra["file_path_reason"] == ""


def test_stage1921_raw_queue_progress_source_guard_closes_unsafe_routes() -> None:
    source = read_python_file(Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/queue/raw_queue_progress.py")

    assert "bool(recent_accum or recent_global)" not in source
    assert "os.fspath(queue_dir)" not in source
    assert "os.fspath(file_path)" not in source
    assert "if not queue_dir or not file_path" not in source
    assert "int(data.get(" not in source
    assert "float(data.get(" not in source
