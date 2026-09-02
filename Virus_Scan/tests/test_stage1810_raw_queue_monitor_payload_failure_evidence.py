from __future__ import annotations

from Virus_Scan.scheduler.evidence.raw_queue_monitor import queue_progress_counts_global


class HostileJobName:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    int_calls = 0
    float_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.int_calls = 0
        cls.float_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not stringify job name")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not repr job name")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not format job name")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not bool job name")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not iterate job name")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not int job name")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not float job name")


def _job_dirs(_queue_dir):
    return "pending", "active", "done", "failed"


def test_stage1810_raw_payload_read_failure_records_evidence_before_file_default() -> None:
    reports: list[tuple[str, str | None, bool]] = []

    def report(stage, exc=None, *, fatal=False, **_kwargs):
        reports.append((stage, type(exc).__name__ if exc is not None else None, fatal))

    counts = queue_progress_counts_global(
        "queue",
        ensure_dirs=lambda _queue_dir: None,
        queue_job_dirs=_job_dirs,
        safe_queue_listdir=lambda directory: ["job.json"] if directory == "pending" else [],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json_file=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("payload unavailable")),
        report=report,
    )

    assert counts["file_pending"] == 1
    assert counts["raw_pending"] == 0
    assert ("queue_progress_raw_payload_read_failed", "RuntimeError", False) in reports


def test_stage1810_raw_payload_failure_preserves_raw_name_fast_path() -> None:
    reports: list[tuple[str, str | None, bool]] = []

    counts = queue_progress_counts_global(
        "queue",
        ensure_dirs=lambda _queue_dir: None,
        queue_job_dirs=_job_dirs,
        safe_queue_listdir=lambda directory: ["raw_job.json"] if directory == "pending" else [],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json_file=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("should not read")),
        report=lambda stage, exc=None, *, fatal=False, **_kwargs: reports.append((stage, type(exc).__name__ if exc is not None else None, fatal)),
    )

    assert counts["file_pending"] == 0
    assert counts["raw_pending"] == 1
    assert reports == []


def test_stage1810_hostile_job_name_rejected_without_hooks() -> None:
    HostileJobName.reset()
    reports: list[tuple[str, str | None, bool]] = []

    counts = queue_progress_counts_global(
        "queue",
        ensure_dirs=lambda _queue_dir: None,
        queue_job_dirs=_job_dirs,
        safe_queue_listdir=lambda directory: [HostileJobName()] if directory == "pending" else [],
        is_job_json_name=lambda _name: True,
        read_json_file=lambda *_args, **_kwargs: {},
        report=lambda stage, exc=None, *, fatal=False, **_kwargs: reports.append((stage, type(exc).__name__ if exc is not None else None, fatal)),
    )

    assert counts["file_pending"] == 0
    assert counts["raw_pending"] == 0
    assert ("queue_progress_job_name_rejected", None, False) in reports
    assert HostileJobName.str_calls == 0
    assert HostileJobName.repr_calls == 0
    assert HostileJobName.format_calls == 0
    assert HostileJobName.bool_calls == 0
    assert HostileJobName.iter_calls == 0
    assert HostileJobName.int_calls == 0
    assert HostileJobName.float_calls == 0
