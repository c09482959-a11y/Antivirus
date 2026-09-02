from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import os
from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_cleanup import cleanup_diagnostic_tmp_files, cleanup_orphan_claim_meta


class HostileCleanupValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("cleanup called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup called __format__")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup called __int__")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup called __float__")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup called __fspath__")


class HostileCleanupName:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup name called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup name called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup name called __format__")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup name called __bool__")


def _reset() -> None:
    HostileCleanupValue.touched = 0
    HostileCleanupName.touched = 0


def test_stage1914_diagnostic_tmp_cleanup_rejects_hostile_names_and_age_without_hooks(tmp_path: Path) -> None:
    _reset()
    diag = tmp_path / "diag"
    diag.mkdir()
    stale = diag / "old.tmp"
    stale.write_text("x", encoding="utf-8")
    os.utime(stale, (1, 1))
    reports = []
    unlinked = []

    cleanup_diagnostic_tmp_files(
        tmp_path,
        failure_diagnostics_dir=lambda _queue_dir: diag,
        safe_listdir=lambda _path: [HostileCleanupName(), "old.tmp"],
        safe_unlink=lambda path, **_kwargs: unlinked.append(Path(path).name),
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
        max_age_sec=HostileCleanupValue(),
    )

    assert unlinked == ["old.tmp"]
    assert reports == []
    assert HostileCleanupValue.touched == 0
    assert HostileCleanupName.touched == 0


def test_stage1914_diagnostic_tmp_cleanup_rejects_hostile_directory_without_fspath() -> None:
    _reset()
    reports = []

    cleanup_diagnostic_tmp_files(
        HostileCleanupValue(),
        failure_diagnostics_dir=lambda queue_dir: queue_dir,
        safe_listdir=lambda _path: [],
        safe_unlink=lambda *_args, **_kwargs: None,
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
    )

    assert reports[0][0][0] == "queue_diagnostic_tmp_cleanup_failed"
    assert reports[0][1]["extra"]["queue_dir_reason"] == "scheduler_path_rejected"
    assert HostileCleanupValue.touched == 0


def test_stage1914_orphan_claim_cleanup_rejects_hostile_limits_names_now_and_unlink_result(tmp_path: Path) -> None:
    _reset()
    active = tmp_path / "active"
    active.mkdir()
    orphan = active / "orphan.json.claim"
    orphan.write_text("{}", encoding="utf-8")
    unlinked = []

    removed = cleanup_orphan_claim_meta(
        active,
        safe_listdir=lambda _path: [HostileCleanupName(), "orphan.json.claim"],
        safe_unlink=lambda path, **_kwargs: unlinked.append(Path(path).name) or HostileCleanupValue(),
        queue_now=lambda: HostileCleanupValue(),
        report=lambda *_args, **_kwargs: None,
        max_remove=HostileCleanupValue(),
        min_age_sec=HostileCleanupValue(),
    )

    assert removed == 0
    assert unlinked == []
    assert HostileCleanupValue.touched == 0
    assert HostileCleanupName.touched == 0


def test_stage1914_orphan_claim_cleanup_does_not_bool_probe_unlink_result(tmp_path: Path) -> None:
    _reset()
    active = tmp_path / "active"
    active.mkdir()
    orphan = active / "orphan.json.claim"
    orphan.write_text("{}", encoding="utf-8")

    removed = cleanup_orphan_claim_meta(
        active,
        safe_listdir=lambda _path: ["orphan.json.claim"],
        safe_unlink=lambda *_args, **_kwargs: HostileCleanupValue(),
        queue_now=lambda: 1000.0,
        report=lambda *_args, **_kwargs: None,
        max_remove=1,
        min_age_sec=0.0,
    )

    assert removed == 0
    assert HostileCleanupValue.touched == 0


def test_stage1914_raw_queue_cleanup_source_guards() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_cleanup.py"))

    assert "key=str" not in source
    assert "str(name" not in source
    assert "name or" not in source
    assert "float(max_age_sec or 600.0)" not in source
    assert "int(max_remove or 0)" not in source
    assert "os.fspath" not in source
    assert "str(p)" not in source
    assert "float(now)" not in source
    assert "safe_unlink(mp" in source
    assert "if safe_unlink" not in source
