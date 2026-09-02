from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_recovery import raw_stage_progress_recent


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


class HostileCounts(dict):
    def get(self, *_args, **_kwargs):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping get touched")

    def __iter__(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping iter touched")


class HostileState(dict):
    def get(self, *_args, **_kwargs):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile state get touched")


def test_stage1923_rejects_hostile_queue_dir_without_fspath_bool_or_str_hooks() -> None:
    HostileValue.touched = 0
    reports = []

    assert raw_stage_progress_recent(
        HostileValue(),
        quiet_sec=HostileValue(),
        progress_counts=lambda _queue_dir: {"raw_pending": 1},
        queue_now=lambda: 100.0,
        state={},
        report=lambda where, exc: reports.append((where, type(exc).__name__)),
        default_quiet_sec=lambda: HostileValue(),
    ) is True

    assert ("raw_stage_progress_quiet_invalid", "ValueError") in reports
    assert ("raw_stage_progress_queue_dir_rejected", "ValueError") in reports
    assert HostileValue.touched == 0


def test_stage1923_rejects_hostile_count_values_and_last_time_without_numeric_or_bool_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    reports = []
    key = str(tmp_path)
    state = {key: (0, HostileValue())}

    assert raw_stage_progress_recent(
        tmp_path,
        quiet_sec=15,
        progress_counts=lambda _queue_dir: {"raw_pending": HostileValue(), "raw_active": 0, "raw_done": 0, "raw_failed": 0},
        queue_now=lambda: 100.0,
        state=state,
        report=lambda where, exc: reports.append((where, type(exc).__name__)),
    ) is True

    assert state[key] == (0, 100.0)
    assert HostileValue.touched == 0


def test_stage1923_rejects_hostile_count_and_state_mapping_methods_without_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    reports = []

    assert raw_stage_progress_recent(
        tmp_path,
        progress_counts=lambda _queue_dir: HostileCounts(raw_pending=HostileValue()),
        queue_now=lambda: HostileValue(),
        state=HostileState(),
        report=lambda where, exc: reports.append((where, type(exc).__name__)),
    ) is True

    assert ("raw_stage_progress_count_failed", "TypeError") in reports
    assert ("raw_stage_progress_now_invalid", "ValueError") in reports
    assert ("raw_stage_progress_state_rejected", "TypeError") in reports
    assert HostileValue.touched == 0


def test_stage1923_raw_queue_recovery_source_guard_closes_unsafe_routes() -> None:
    source = read_python_file(Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/queue/raw_queue_recovery.py")

    assert "os.fspath" not in source
    assert "quiet = float" not in source
    assert "now = float" not in source
    assert "float(last_time" not in source
    assert "int(counts" not in source
    assert "counts.get" not in source
    assert "last_time or now" not in source
    assert "state.get" not in source
