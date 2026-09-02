"""Stage 1844: raw queue monitor explicit failure evidence closure."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.raw_queue_monitor import (
    queue_io_pressure_sample,
    queue_progress_counts_global,
)


def _job_dirs(_queue_dir):
    return "pending", "active", "done", "failed"


def test_stage1844_payload_read_failure_reports_and_preserves_file_count_without_sentinel_bool() -> None:
    reports: list[tuple[str, str | None, bool]] = []

    counts = queue_progress_counts_global(
        "queue",
        ensure_dirs=lambda _queue_dir: None,
        queue_job_dirs=_job_dirs,
        safe_queue_listdir=lambda directory: ["job.json"] if directory == "pending" else [],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json_file=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("payload unavailable")),
        report=lambda stage, exc=None, *, fatal=False, **_kwargs: reports.append(
            (stage, type(exc).__name__ if exc is not None else None, fatal)
        ),
    )

    assert counts["file_pending"] == 1
    assert counts["raw_pending"] == 0
    assert ("queue_progress_raw_payload_read_failed", "RuntimeError", False) in reports


def test_stage1844_queue_listdir_failure_records_owned_queue_dir_text(tmp_path: Path) -> None:
    reports: list[tuple[str, dict[str, object]]] = []

    def listdir(path):
        if Path(path).name == "active":
            raise OSError("denied")
        return []

    sample = queue_io_pressure_sample(
        tmp_path,
        safe_queue_listdir=listdir,
        report=lambda stage, exc=None, *, fatal=False, extra=None: reports.append((stage, extra or {})),
        psutil_module=None,
        environ={},
        sleep=lambda _delay: None,
        time_fn=lambda: 1.0,
    )

    assert sample["queue_files"] == 0
    listdir_report = next(extra for stage, extra in reports if stage == "io_pressure_queue_list_failed")
    assert listdir_report["queue_dir"] == tmp_path.as_posix()
    assert listdir_report["subdir"] == "active"
    assert listdir_report["queue_listdir_failure"]["queue_listdir_failed"] is True
    assert listdir_report["queue_listdir_failure"]["scheduler_filesystem_unavailable"] is True


def test_stage1844_raw_queue_monitor_sources_remove_repaired_sentinel_and_direct_listdir_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    monitor_source = (root / "scheduler/evidence/raw_queue_monitor.py").read_text(encoding="utf-8")
    support_source = (root / "scheduler/evidence/raw_queue_monitor_support.py").read_text(encoding="utf-8")
    combined_source = "\n".join((monitor_source, support_source))

    for snippet in ("return False", "os.fspath(q)"):
        assert snippet not in combined_source

    assert "safe_queue_listdir(directory)," not in monitor_source
    assert "queue_listdir_names(safe_queue_listdir(directory), context=directory)" in support_source
