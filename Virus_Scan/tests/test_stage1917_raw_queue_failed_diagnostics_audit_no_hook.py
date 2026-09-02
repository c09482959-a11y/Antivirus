from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import json
from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_failed_diagnostics import repair_failed_queue_job_diagnostics
from Virus_Scan.scheduler.queue.raw_queue_failure_audit import collect_failed_queue_report, summarize_failed_queue_report


class HostileFailedQueueValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("failed queue called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue called __format__")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue called __int__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue called __iter__")


class HostileFailedQueueName:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue name called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue name called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue name called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue name called __format__")


class HostileFailedQueueException(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue exception called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue exception called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failed queue exception called __format__")


def _reset() -> None:
    HostileFailedQueueValue.touched = 0
    HostileFailedQueueName.touched = 0
    HostileFailedQueueException.touched = 0


def _job_dirs(root: Path) -> tuple[Path, Path, Path, Path]:
    paths = tuple(root / name for name in ("pending", "active", "done", "failed"))
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
    return paths  # type: ignore[return-value]


def test_stage1917_failed_diagnostic_repair_rejects_hostile_names_and_values_without_hooks(tmp_path: Path) -> None:
    _reset()
    failed = _job_dirs(tmp_path)[3]
    job = failed / "job.json"
    job.write_text(json.dumps({"attempt": 3, "queue_info": {"worker_pid": 321}}), encoding="utf-8")

    repaired = repair_failed_queue_job_diagnostics(
        tmp_path,
        queue_job_dirs=_job_dirs,
        safe_queue_listdir=lambda _path: [HostileFailedQueueName(), "job.json"],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json_file=lambda path, default=None: json.loads(Path(path).read_text(encoding="utf-8")),
        default_failure_info=lambda **kwargs: kwargs,
        make_json_safe=lambda value: value,
        queue_safe_unlink=lambda *_args, **_kwargs: True,
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        log_error=lambda _msg: None,
    )

    data = json.loads(job.read_text(encoding="utf-8"))
    assert repaired == 1
    assert data["failure_info"]["worker_pid"] == 321
    assert HostileFailedQueueName.touched == 0


def test_stage1917_failed_diagnostic_log_error_does_not_stringify_hostile_exception(tmp_path: Path) -> None:
    _reset()
    messages: list[str] = []

    repaired = repair_failed_queue_job_diagnostics(
        tmp_path,
        queue_job_dirs=lambda _queue_dir: (_ for _ in ()).throw(HostileFailedQueueException(HostileFailedQueueValue())),
        safe_queue_listdir=lambda _path: [],
        is_job_json_name=lambda _name: True,
        read_json_file=lambda _path, default=None: {},
        default_failure_info=lambda **kwargs: kwargs,
        make_json_safe=lambda value: value,
        queue_safe_unlink=lambda *_args, **_kwargs: True,
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        log_error=lambda msg: messages.append(msg),
    )

    assert repaired == 0
    assert messages == ["process queue failed-job diagnostic repair failed: HostileFailedQueueException: scheduler diagnostic detail unavailable without caller hooks"]
    assert HostileFailedQueueException.touched == 0
    assert HostileFailedQueueValue.touched == 0


def test_stage1917_collect_failed_report_rejects_hostile_names_and_values_without_hooks(tmp_path: Path) -> None:
    _reset()
    failed = _job_dirs(tmp_path)[3]
    (failed / "001.json").write_text(json.dumps({"file": "sample.bin", "queue_info": {"worker_pid": 123}}), encoding="utf-8")

    report = collect_failed_queue_report(
        tmp_path,
        queue_job_dirs=_job_dirs,
        safe_queue_listdir=lambda _path: [HostileFailedQueueName(), "001.json"],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json_file=lambda path, default=None: json.loads(Path(path).read_text(encoding="utf-8")),
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
        log_error=lambda _msg: None,
    )

    assert report[0]["file"] == "sample.bin"
    assert report[0]["worker_pid"] == 123
    assert HostileFailedQueueName.touched == 0


def test_stage1917_failed_report_log_error_and_summary_reject_hooks() -> None:
    _reset()
    messages: list[str] = []

    report = collect_failed_queue_report(
        HostileFailedQueueValue(),
        queue_job_dirs=lambda _queue_dir: (_ for _ in ()).throw(HostileFailedQueueException(HostileFailedQueueValue())),
        safe_queue_listdir=lambda _path: [],
        is_job_json_name=lambda _name: True,
        read_json_file=lambda _path, default=None: {},
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
        log_error=lambda msg: messages.append(msg),
    )
    summary = summarize_failed_queue_report(
        [{"job_type": HostileFailedQueueValue(), "stage": HostileFailedQueueValue(), "exception_type": HostileFailedQueueValue(), "error": HostileFailedQueueValue()}],
        limit=HostileFailedQueueValue(),
    )

    assert report == []
    assert messages == ["process queue failed-job report collection failed: HostileFailedQueueException: scheduler diagnostic detail unavailable without caller hooks"]
    assert summary == [(('file', 'unknown', 'unknown', ''), 1)]
    assert HostileFailedQueueException.touched == 0
    assert HostileFailedQueueValue.touched == 0


def test_stage1917_failed_diagnostics_and_audit_source_guards() -> None:
    diagnostics = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_failed_diagnostics.py"))
    audit = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_failure_audit.py"))

    for source in (diagnostics, audit):
        assert "isinstance(item, dict)" not in source
        assert "item.get(" not in source
        assert "log_error(f" not in source
        assert "str(fr.get" not in source
        assert "int(limit or 0)" not in source
        assert "for raw_name in queue_listdir_names(safe_queue_listdir(failed_path), context=failed_path):" in source
    assert "hist[-1] if isinstance" not in diagnostics
    assert "str(path) + \".repair.tmp\"" not in diagnostics
