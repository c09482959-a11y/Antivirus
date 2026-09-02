from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_duplicates import duplicate_live_guard


class HostileDuplicateValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("duplicate guard called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate guard called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate guard called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate guard called __format__")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate guard called __fspath__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate guard called __iter__")


class HostileDuplicateName:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate name called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate name called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate name called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate name called __format__")


class HostileDuplicateException(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate exception called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate exception called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate exception called __format__")


def _reset() -> None:
    HostileDuplicateValue.touched = 0
    HostileDuplicateName.touched = 0
    HostileDuplicateException.touched = 0


def _dirs(root: Path) -> tuple[Path, Path, Path, Path]:
    dirs = tuple(root / name for name in ("pending", "active", "done", "failed"))
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
    return dirs  # type: ignore[return-value]


def test_stage1916_duplicate_guard_skips_hostile_listdir_names_without_hooks(tmp_path: Path) -> None:
    _reset()
    pending, active, done, failed = _dirs(tmp_path)
    claim = active / "claim.json"
    claim.write_text("{}", encoding="utf-8")

    allowed = duplicate_live_guard(
        tmp_path,
        claim,
        {"file": "sample.bin"},
        job_identity=lambda _job, _source_name=None: "raw:sample:0",
        job_dirs=lambda _queue_dir: (pending, active, done, failed),
        safe_listdir=lambda _directory: [HostileDuplicateName(), "note.txt"],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json=lambda *_args, **_kwargs: {"file": "sample.bin"},
        merge_claim_meta=lambda _path, record=None: record or {},
        quarantine_job=lambda *_args, **_kwargs: True,
        report=lambda *_args, **_kwargs: None,
    )

    assert allowed is True
    assert HostileDuplicateName.touched == 0


def test_stage1916_duplicate_guard_rejects_hostile_claim_path_before_filesystem_hooks(tmp_path: Path) -> None:
    _reset()
    reports: list[tuple[str, dict[str, object]]] = []

    allowed = duplicate_live_guard(
        tmp_path,
        HostileDuplicateValue(),
        {"file": "sample.bin"},
        job_identity=lambda _job, _source_name=None: "raw:sample:0",
        job_dirs=lambda _queue_dir: (_ for _ in ()).throw(AssertionError("job_dirs must not run")),
        safe_listdir=lambda _directory: (_ for _ in ()).throw(AssertionError("listdir must not run")),
        is_job_json_name=lambda _name: True,
        read_json=lambda *_args, **_kwargs: {},
        merge_claim_meta=lambda _path, record=None: record or {},
        quarantine_job=lambda *_args, **_kwargs: True,
        report=lambda where, _exc, **kwargs: reports.append((where, kwargs)),
    )

    assert allowed is False
    assert reports[0][0] == "queue_duplicate_live_guard_failed_closed"
    assert reports[0][1]["extra"]["claim_path_reason"] == "scheduler_path_rejected"
    assert HostileDuplicateValue.touched == 0


def test_stage1916_duplicate_guard_read_failure_reports_path_without_fspath(tmp_path: Path) -> None:
    _reset()
    pending, active, done, failed = _dirs(tmp_path)
    claim = active / "claim.json"
    claim.write_text("{}", encoding="utf-8")
    duplicate = done / "done.json"
    duplicate.write_text("{}", encoding="utf-8")
    reports: list[tuple[str, dict[str, object]]] = []

    allowed = duplicate_live_guard(
        tmp_path,
        claim,
        {"file": "sample.bin"},
        job_identity=lambda _job, _source_name=None: "raw:sample:0",
        job_dirs=lambda _queue_dir: (pending, active, done, failed),
        safe_listdir=lambda directory: ["done.json"] if Path(directory) == done else [],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json=lambda *_args, **_kwargs: HostileDuplicateValue(),
        merge_claim_meta=lambda _path, record=None: record or {},
        quarantine_job=lambda *_args, **_kwargs: True,
        report=lambda where, _exc, **kwargs: reports.append((where, kwargs)),
    )

    assert allowed is False
    assert reports[0][0] == "queue_duplicate_live_guard_read_failed"
    assert reports[0][1]["extra"]["path"].endswith("done.json")
    assert HostileDuplicateValue.touched == 0


def test_stage1916_duplicate_guard_failed_closed_does_not_stringify_hostile_exception(tmp_path: Path) -> None:
    _reset()
    claim = tmp_path / "active" / "claim.json"
    claim.parent.mkdir(parents=True)
    claim.write_text("{}", encoding="utf-8")
    reports: list[str] = []

    allowed = duplicate_live_guard(
        tmp_path,
        claim,
        {"file": "sample.bin"},
        job_identity=lambda _job, _source_name=None: "raw:sample:0",
        job_dirs=lambda _queue_dir: (_ for _ in ()).throw(HostileDuplicateException(HostileDuplicateValue())),
        safe_listdir=lambda _directory: [],
        is_job_json_name=lambda _name: True,
        read_json=lambda *_args, **_kwargs: {},
        merge_claim_meta=lambda _path, record=None: record or {},
        quarantine_job=lambda *_args, **_kwargs: True,
        report=lambda where, _exc, **_kwargs: reports.append(where),
    )

    assert allowed is False
    assert reports == ["queue_duplicate_live_guard_failed_closed"]
    assert HostileDuplicateException.touched == 0
    assert HostileDuplicateValue.touched == 0


def test_stage1916_duplicate_guard_quarantine_result_uses_exact_true_only(tmp_path: Path) -> None:
    _reset()
    pending, active, done, failed = _dirs(tmp_path)
    claim = active / "claim.json"
    claim.write_text("{}", encoding="utf-8")
    duplicate = done / "done.json"
    duplicate.write_text("{}", encoding="utf-8")
    reports: list[str] = []

    allowed = duplicate_live_guard(
        tmp_path,
        claim,
        {"file": "sample.bin"},
        job_identity=lambda _job, _source_name=None: "raw:sample:0",
        job_dirs=lambda _queue_dir: (pending, active, done, failed),
        safe_listdir=lambda directory: ["done.json"] if Path(directory) == done else [],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json=lambda *_args, **_kwargs: {"file": "sample.bin"},
        merge_claim_meta=lambda _path, record=None: record or {},
        quarantine_job=lambda *_args, **_kwargs: HostileDuplicateValue(),
        report=lambda where, _exc, **_kwargs: reports.append(where),
    )

    assert allowed is False
    assert reports == ["queue_duplicate_live_guard_quarantine_current_failed"]
    assert HostileDuplicateValue.touched == 0


def test_stage1916_raw_queue_duplicate_source_guards() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_duplicates.py"))

    assert "import os" not in source
    assert "os.fspath" not in source
    assert "key=str" not in source
    assert "isinstance(job, dict)" not in source
    assert "isinstance(other, dict)" not in source
    assert "if claim_path else" not in source
    assert "not quarantine_job" not in source
    assert "return False" not in source
    assert "queue_listdir_names(safe_listdir(d), context=d)" in source
