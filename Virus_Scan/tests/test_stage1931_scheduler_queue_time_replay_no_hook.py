from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.time import queue_path_mtime_age
from Virus_Scan.scheduler.queue.workload_identity import _sniff_workload_identity
from Virus_Scan.scheduler.replay.replay_projection import canonical_replay_label


class HostilePath:
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


class HostileNumeric:
    float_calls = 0
    str_calls = 0
    repr_calls = 0

    def __float__(self):  # pragma: no cover - must not execute
        type(self).float_calls += 1
        raise AssertionError("numeric __float__ hook executed")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).str_calls += 1
        raise AssertionError("numeric __str__ hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).repr_calls += 1
        raise AssertionError("numeric __repr__ hook executed")


class HostileFieldName:
    str_calls = 0
    repr_calls = 0
    format_calls = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).str_calls += 1
        raise AssertionError("field __str__ hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).repr_calls += 1
        raise AssertionError("field __repr__ hook executed")

    def __format__(self, spec):  # pragma: no cover - must not execute
        type(self).format_calls += 1
        raise AssertionError("field __format__ hook executed")


def _reset_hostile_counters() -> None:
    for cls in (HostilePath, HostileNumeric, HostileFieldName):
        for name in tuple(vars(cls)):
            if name.endswith("_calls"):
                setattr(cls, name, 0)


def test_stage1931_queue_mtime_rejects_hostile_path_before_hooks() -> None:
    _reset_hostile_counters()
    seen: list[tuple[tuple[object, ...], dict[str, object]]] = []

    result = queue_path_mtime_age(
        HostilePath(),
        now=100.0,
        record_suppressed=lambda *args, **kwargs: seen.append((args, kwargs)),
    )

    assert result is None
    assert seen and seen[0][0][0] == "process_queue_active_claim_mtime_unavailable"
    assert seen[0][1]["extra"]["path_unavailable_reason"] == "scheduler_path_rejected"
    assert HostilePath.str_calls == 0
    assert HostilePath.repr_calls == 0
    assert HostilePath.fspath_calls == 0
    assert HostilePath.format_calls == 0


def test_stage1931_queue_mtime_rejects_hostile_now_before_numeric_hooks(tmp_path: Path) -> None:
    _reset_hostile_counters()
    claim = tmp_path / "claim.json"
    claim.write_text("{}", encoding="utf-8")
    seen: list[tuple[tuple[object, ...], dict[str, object]]] = []

    result = queue_path_mtime_age(
        claim,
        now=HostileNumeric(),  # type: ignore[arg-type]
        record_suppressed=lambda *args, **kwargs: seen.append((args, kwargs)),
    )

    assert result is None
    assert seen and seen[0][1]["extra"]["time_unavailable_reason"] == "process_queue_active_claim_now_rejected"
    assert HostileNumeric.float_calls == 0
    assert HostileNumeric.str_calls == 0
    assert HostileNumeric.repr_calls == 0


def test_stage1931_workload_identity_rejects_hostile_path_before_fspath_hooks() -> None:
    _reset_hostile_counters()

    identity = _sniff_workload_identity(HostilePath())  # type: ignore[arg-type]

    assert identity["path_unavailable_reason"] == "scheduler_path_rejected"
    assert HostilePath.str_calls == 0
    assert HostilePath.repr_calls == 0
    assert HostilePath.fspath_calls == 0
    assert HostilePath.format_calls == 0


def test_stage1931_replay_label_rejects_hostile_field_name_before_format_hooks() -> None:
    _reset_hostile_counters()

    with pytest.raises(RuntimeError, match="scheduler replay result missing replay field"):
        canonical_replay_label(None, field_name=HostileFieldName())  # type: ignore[arg-type]

    assert HostileFieldName.str_calls == 0
    assert HostileFieldName.repr_calls == 0
    assert HostileFieldName.format_calls == 0


def test_stage1931_removed_scheduler_queue_replay_unsafe_markers() -> None:
    root = Path(__file__).resolve().parents[1] / "scheduler"
    forbidden = {
        "queue/time.py": (
            "float(now if now is not None else time.time())",
            "Path(path).stat()",
            "str(path)",
        ),
        "queue/workload_identity.py": ("os.fspath(filesystem_path)",),
        "replay/replay_comparison_record.py": (
            'field_name=f"verdict for {job_id}"',
            'field_name=f"engine routing for {job_id}"',
        ),
        "replay/replay_mismatch.py": (
            'f"unsupported_replay_record_{index}"',
            'f"missing_replay_job_id_{index}"',
        ),
        "replay/replay_projection.py": (
            'f"{base_identity}::{archive_identity}"',
            'f"scheduler replay result missing {field_name}"',
            "isinstance(value, Mapping)",
            "value.items()",
        ),
        "replay/replay_projection_failure.py": ('fallback="scheduler replay projection failed"',),
    }
    for relative_path, markers in forbidden.items():
        source = (root / relative_path).read_text(encoding="utf-8")
        for marker in markers:
            assert marker not in source, f"{relative_path}: {marker}"
