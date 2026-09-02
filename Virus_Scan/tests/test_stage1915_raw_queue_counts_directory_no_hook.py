from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_counts import pending_file_jobs, raw_queue_live_count
from Virus_Scan.scheduler.queue.raw_queue_directory import enqueue_guard


class HostileQueueValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("raw queue counts called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue counts called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue counts called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue counts called __format__")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue counts called __int__")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue counts called __float__")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue counts called __fspath__")


class HostileQueueName:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue name called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue name called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue name called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue name called __format__")


class HostileQueueException(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue exception called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue exception called __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("raw queue exception called __format__")


def _reset() -> None:
    HostileQueueValue.touched = 0
    HostileQueueName.touched = 0
    HostileQueueException.touched = 0


def test_stage1915_pending_file_jobs_rejects_hostile_names_without_hooks(tmp_path: Path) -> None:
    _reset()
    pending = tmp_path / "pending"
    pending.mkdir()
    jobs = {"file.json": {"job_type": "file"}, "raw.json": {"job_type": "raw_stage"}}

    count = pending_file_jobs(
        tmp_path,
        queue_job_dirs=lambda qd: (pending, qd / "active", qd / "done", qd / "failed"),
        safe_listdir=lambda _path: [HostileQueueName(), "file.json", "raw.json"],
        read_json_file=lambda path, default=None: jobs[path.name],
        report=lambda *_args, **_kwargs: None,
    )

    assert count == 1
    assert HostileQueueName.touched == 0


def test_stage1915_pending_file_jobs_reports_hostile_queue_dir_without_path_hooks() -> None:
    _reset()
    reports: list[tuple[tuple[object, ...], dict[str, object]]] = []

    count = pending_file_jobs(
        HostileQueueValue(),
        queue_job_dirs=lambda _queue_dir: (_ for _ in ()).throw(RuntimeError("blocked")),
        safe_listdir=lambda _path: [],
        read_json_file=lambda _path, default=None: {},
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
    )

    assert count == -1
    assert reports[0][0][0] == "raw_pending_file_jobs_unknown"
    assert reports[0][1]["extra"]["queue_dir_reason"] == "scheduler_path_rejected"
    assert HostileQueueValue.touched == 0


def test_stage1915_raw_queue_live_count_rejects_hostile_count_values_without_hooks() -> None:
    _reset()

    live = raw_queue_live_count(
        "queue",
        queue_progress_counts=lambda _queue_dir: {"raw_pending": HostileQueueValue(), "raw_active": HostileQueueValue()},
        report=lambda *_args, **_kwargs: None,
        live_hard_cap=17,
    )

    assert live == 0
    assert HostileQueueValue.touched == 0


def test_stage1915_raw_queue_live_count_failure_uses_safe_hard_cap_without_hooks() -> None:
    _reset()
    reports: list[str] = []

    live = raw_queue_live_count(
        HostileQueueValue(),
        queue_progress_counts=lambda _queue_dir: (_ for _ in ()).throw(HostileQueueException(HostileQueueValue())),
        report=lambda where, _exc: reports.append(where),
        live_hard_cap=HostileQueueValue(),
    )

    assert live == 900
    assert reports == ["raw_live_count_failed_closed"]
    assert HostileQueueValue.touched == 0
    assert HostileQueueException.touched == 0


def test_stage1915_enqueue_guard_failed_closed_without_except_return_shortcut(tmp_path: Path) -> None:
    _reset()
    suppressed: list[str] = []

    admitted = enqueue_guard(
        tmp_path,
        {},
        identity="raw:file:sample:0",
        job_identity=lambda *_args, **_kwargs: "unused",
        existing_identities=lambda *_args, **_kwargs: (_ for _ in ()).throw(HostileQueueException(HostileQueueValue())),
        record_suppressed=lambda where, _exc: suppressed.append(where),
        recoverable_exceptions=(RuntimeError,),
    )

    assert admitted is False
    assert suppressed == ["queue_enqueue_guard_failed_closed"]
    assert HostileQueueValue.touched == 0
    assert HostileQueueException.touched == 0


def test_stage1915_raw_queue_counts_directory_source_guards() -> None:
    counts_source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_counts.py"))
    directory_source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_directory.py"))

    assert "str(name" not in counts_source
    assert "str(queue_dir" not in counts_source
    assert "int(qc.get" not in counts_source
    assert "or 0" not in counts_source
    assert "int(live_hard_cap or 900)" not in counts_source
    assert "isinstance(job, dict)" not in counts_source
    assert "for raw_name in queue_listdir_names(safe_listdir(pending), context=pending):" in counts_source
    assert "except recoverable_exceptions as exc:\n        record_suppressed(\"queue_enqueue_guard_failed_closed\", exc)\n        return False" not in directory_source
