from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.phase_ledger import _record_queue_snapshot, _validate_worker_lifecycle_cleanup


class HostileValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iter")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items")


class HostileDict(dict):
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


def _queue_dirs(root: Path) -> None:
    for name in ("pending", "active", "done", "failed", "quarantine"):
        (root / name).mkdir(parents=True, exist_ok=True)


def test_stage1902_queue_snapshot_rejects_phase_and_integrity_without_hooks(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    HostileValue.touched = 0
    HostileDict.touched = 0

    snapshot = _record_queue_snapshot(tmp_path, HostileValue(), integrity_summary=HostileDict({"duplicates": 3}), total=0)

    assert snapshot.phase == "unknown"
    assert snapshot.duplicate_count == 0
    assert snapshot.invalid_record_count == 0
    assert HostileValue.touched == 0
    assert HostileDict.touched == 0


def test_stage1902_worker_cleanup_projects_live_and_pending_without_hooks(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    HostileValue.touched = 0

    with pytest.raises(RuntimeError, match="live child workers"):
        _validate_worker_lifecycle_cleanup(tmp_path, [], live_child_workers=[HostileValue()])
    assert HostileValue.touched == 0

    with pytest.raises(RuntimeError, match="pending queue files"):
        _validate_worker_lifecycle_cleanup(tmp_path, [], pending_queue_files=[HostileValue()])
    assert HostileValue.touched == 0


def test_stage1902_phase_ledger_source_has_no_dict_str_or_fstring_routes() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/phase_ledger.py"))

    assert "dict(integrity_summary or {})" not in source
    assert 'str(phase or "unknown")' not in source
    assert "tuple(str(worker)" not in source
    assert "tuple(str(path)" not in source
    assert "raise RuntimeError(f\"scheduler finalization has live child workers" not in source
    assert "raise RuntimeError(f\"scheduler finalization has pending queue files" not in source
