from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_live_work import (
    RawQueueLiveWorkDependencies,
    mark_stalled_accumulator,
    normalize_live_accumulator_counts,
    raw_queue_has_live_work,
)
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileBoundaryValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - fails if hook boundary regresses
        type(self).touched += 1
        raise AssertionError("bool hook touched")

    def __str__(self):  # pragma: no cover - fails if hook boundary regresses
        type(self).touched += 1
        raise AssertionError("str hook touched")

    def __iter__(self):  # pragma: no cover - fails if hook boundary regresses
        type(self).touched += 1
        raise AssertionError("iter hook touched")

    def __len__(self):  # pragma: no cover - fails if hook boundary regresses
        type(self).touched += 1
        raise AssertionError("len hook touched")

    def __getitem__(self, _key):  # pragma: no cover - fails if hook boundary regresses
        type(self).touched += 1
        raise AssertionError("getitem hook touched")

    def __float__(self):  # pragma: no cover - fails if hook boundary regresses
        type(self).touched += 1
        raise AssertionError("float hook touched")


class BrokenOrderedUnique:
    def __call__(self, _tags: object) -> list[object]:
        raise RuntimeError("ordered unique unavailable")


def _dirs(root: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    dirs = tuple(root / name for name in ("pending", "active", "done", "failed", "accum", "locks"))
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
    return dirs


def _deps(root: Path, **overrides: object) -> RawQueueLiveWorkDependencies:
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


def test_stage2130_raw_queue_live_work_source_has_typed_decision_boundary() -> None:
    source = read_python_file(Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/queue/raw_queue_live_work.py")

    assert "from typing import Any" not in source
    assert "dict[str, Any]" not in source
    assert "Callable[[Any]" not in source
    assert "RawQueueNameDecision" in source
    assert "RawAccumulatorMappingDecision" in source
    assert "return None" not in source


def test_stage2130_hostile_accumulator_data_is_rejected_without_hooks(tmp_path: Path) -> None:
    HostileBoundaryValue.touched = 0
    hostile = HostileBoundaryValue()
    pending, active, done, failed, accum, locks = _dirs(tmp_path)
    deps = _deps(
        tmp_path,
        global_raw_dirs=lambda _queue_dir: (pending, active, done, failed, accum, locks),
        safe_listdir=lambda path: ("record.json",) if path == accum else (),
        read_json=lambda _path, default=None: hostile,
    )

    assert raw_queue_has_live_work(tmp_path, deps) is False
    assert normalize_live_accumulator_counts(hostile) == {"expected": 0, "completed": 0, "failed": 0}
    assert HostileBoundaryValue.touched == 0


def test_stage2130_mark_stalled_accumulator_preserves_explicit_degraded_evidence(tmp_path: Path) -> None:
    HostileBoundaryValue.touched = 0
    hostile = HostileBoundaryValue()
    writes: list[tuple[object, object, dict[str, object], dict[str, object]]] = []
    deps = _deps(
        tmp_path,
        ordered_unique_tags=BrokenOrderedUnique(),
        write_json_durable=lambda tmp, final, payload, **kwargs: writes.append((tmp, final, payload, kwargs)) or True,
    )

    mark_stalled_accumulator(
        tmp_path / "accum" / "record.json",
        {"expected": "3", "completed": 1, "failed": 0, "tags": ["kept", hostile], "raw_failures": [hostile]},
        hostile,
        deps,
    )

    assert HostileBoundaryValue.touched == 0
    assert writes
    payload = writes[0][2]
    assert payload["closed"] is True
    assert payload["degraded"] is True
    assert payload["completed"] == 3
    assert payload["failed"] == 2
    assert payload["failure_info"] == {
        "stage": "raw_accumulator_stalled",
        "error": "raw accumulator stale for 0.0s",
        "missing_chunks": 2,
    }
