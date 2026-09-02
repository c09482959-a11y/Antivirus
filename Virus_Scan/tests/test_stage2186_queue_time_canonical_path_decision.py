from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.time import queue_path_mtime_age


class Stage2186HostilePath:
    str_calls = 0
    repr_calls = 0
    fspath_calls = 0
    format_calls = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).str_calls += 1
        raise AssertionError("path __str__ hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).repr_calls += 1
        raise AssertionError("path __repr__ hook executed")

    def __fspath__(self):  # pragma: no cover - must not execute
        type(self).fspath_calls += 1
        raise AssertionError("path __fspath__ hook executed")

    def __format__(self, spec):  # pragma: no cover - must not execute
        type(self).format_calls += 1
        raise AssertionError("path __format__ hook executed")


def _reset_hostile_path() -> None:
    Stage2186HostilePath.str_calls = 0
    Stage2186HostilePath.repr_calls = 0
    Stage2186HostilePath.fspath_calls = 0
    Stage2186HostilePath.format_calls = 0


def test_stage2186_queue_mtime_uses_canonical_path_text_boundary() -> None:
    source = Path("Virus_Scan/scheduler/queue/time.py").read_text(encoding="utf-8")

    assert "def _queue_path_text" not in source
    assert "def _unavailable_mtime_age" not in source
    assert "scheduler_path_text(filesystem_path)" in source
    assert "PurePath.__str__" not in source


def test_stage2186_queue_mtime_rejects_hostile_path_with_replayable_evidence() -> None:
    _reset_hostile_path()
    seen: list[tuple[tuple[object, ...], dict[str, object]]] = []

    result = queue_path_mtime_age(
        Stage2186HostilePath(),
        now=100.0,
        record_suppressed=lambda *args, **kwargs: seen.append((args, kwargs)),
    )

    assert result is None
    assert seen
    args, kwargs = seen[0]
    assert args[0] == "process_queue_active_claim_mtime_unavailable"
    assert kwargs["extra"] == {
        "path": "",
        "path_unavailable_reason": "scheduler_path_rejected",
    }
    assert kwargs["fatal"] is False
    assert Stage2186HostilePath.str_calls == 0
    assert Stage2186HostilePath.repr_calls == 0
    assert Stage2186HostilePath.fspath_calls == 0
    assert Stage2186HostilePath.format_calls == 0
