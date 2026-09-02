from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_live_work import (
    RawQueueLiveWorkDependencies,
    mark_stalled_accumulator,
    raw_queue_has_live_work,
)


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

    def endswith(self, *_args, **_kwargs):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile endswith hook touched")


class HostileOrderedUnique:
    def __call__(self, _tags):
        raise RuntimeError("ordered unique unavailable")


def _dirs(root: Path):
    dirs = tuple(root / name for name in ("pending", "active", "done", "failed", "accum", "locks"))
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def _deps(root: Path, **overrides) -> RawQueueLiveWorkDependencies:
    pending, active, done, failed, accum, locks = _dirs(root)
    values = {
        "global_raw_dirs": lambda _queue_dir: (pending, active, done, failed, accum, locks),
        "read_json": lambda _path, default=None: default,
        "raw_accumulator_store": object(),
        "ordered_unique_tags": lambda tags: list(dict.fromkeys(tags)),
        "write_json_durable": lambda *_args, **_kwargs: True,
        "record_suppressed": lambda _where, _exc: None,
        "safe_listdir": lambda _path: (),
    }
    values.update(overrides)
    return RawQueueLiveWorkDependencies(**values)


def test_stage1920_live_work_rejects_hostile_listdir_names_without_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    hostile_name = HostileValue()
    deps = _deps(tmp_path, safe_listdir=lambda _path: (hostile_name,))

    assert raw_queue_has_live_work(tmp_path, deps) is False
    assert HostileValue.touched == 0


def test_stage1920_live_work_rejects_hostile_accumulator_counts_without_numeric_hooks(tmp_path: Path) -> None:
    HostileValue.touched = 0
    hostile_value = HostileValue()
    pending, active, done, failed, accum, locks = _dirs(tmp_path)
    deps = _deps(
        tmp_path,
        global_raw_dirs=lambda _queue_dir: (pending, active, done, failed, accum, locks),
        safe_listdir=lambda path: ("record.json",) if path == accum else (),
        read_json=lambda _path, default=None: {"expected": hostile_value, "completed": hostile_value, "failed": hostile_value},
    )

    assert raw_queue_has_live_work(tmp_path, deps) is False
    assert HostileValue.touched == 0


def test_stage1920_mark_stalled_accumulator_uses_no_hook_age_tags_and_errors(tmp_path: Path) -> None:
    HostileValue.touched = 0
    hostile = HostileValue()
    writes = []
    deps = _deps(
        tmp_path,
        ordered_unique_tags=HostileOrderedUnique(),
        write_json_durable=lambda tmp, final, payload, **kwargs: writes.append((tmp, final, payload, kwargs)) or True,
    )

    mark_stalled_accumulator(
        tmp_path / "accum" / "record.json",
        {"expected": "2", "completed": "1", "failed": False, "tags": ["kept", hostile], "raw_failures": [hostile]},
        hostile,
        deps,
    )

    assert HostileValue.touched == 0
    assert writes
    payload = writes[0][2]
    assert payload["failed"] == 1
    assert payload["completed"] == 2
    assert "kept" in payload["tags"]
    assert "raw_accumulator_stalled" in payload["tags"]
    assert payload["raw_failures"][-1]["error"] == "raw accumulator stale for 0.0s; missing=1"
    assert payload["failure_info"]["error"] == "raw accumulator stale for 0.0s"


def test_stage1920_raw_queue_live_work_source_guard_closes_unsafe_routes() -> None:
    source = read_python_file(Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/queue/raw_queue_live_work.py")

    assert "str(name)" not in source
    assert "queue_listdir_names(deps.safe_listdir(directory), context=directory)" in source
    assert "deps.safe_listdir(accum)," not in source
    assert "return False\n    except" not in source
    assert "return True\n    return live" not in source
    assert 'f"raw accumulator stale' not in source
    assert 'raise RuntimeError(f"raw accumulator stall mark failed' not in source
