
"""Stage2061: remaining scheduler sentinel returns become explicit unavailable evidence."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.evidence.raw_queue_monitor_support import safe_queue_names
from Virus_Scan.scheduler.queue.raw_queue_progress import file_has_recent_raw_owner_progress
from Virus_Scan.scheduler.workers.lifecycle_boundary import SchedulerIsolationBoundary, WorkerLifecycleEvent


class _StoreWithMissingMtime:
    def __init__(self, queue_dir: Path, file_id: str) -> None:
        self.path = queue_dir / (file_id + ".missing.json")

    def load(self) -> dict[str, object]:
        return {"file_id": "fid", "expected": 2, "completed": 1, "updated_at": 0.0}

    @staticmethod
    def is_complete(_data: object) -> bool:
        return False


def test_stage2061_safe_queue_names_reports_typed_listdir_failure_evidence() -> None:
    reports: list[tuple[str, object, bool, dict[str, object]]] = []

    names = safe_queue_names(
        "queue/active",
        safe_queue_listdir=lambda _directory: (_ for _ in ()).throw(OSError("denied")),
        report=lambda stage, exc=None, *, fatal=False, extra=None: reports.append((stage, exc, fatal, extra or {})),
        failure_stage="queue_progress_counts_failed",
    )

    assert names == tuple()
    assert reports[0][0] == "queue_progress_counts_failed"
    assert reports[0][2] is False
    failure = reports[0][3]["queue_listdir_failure"]
    assert failure["queue_listdir_failed"] is True
    assert failure["scheduler_filesystem_unavailable"] is True
    assert failure["reason"] == "queue_listdir_dependency_failed"
    assert failure["error_evidence"]["error_type"] == "OSError"


def test_stage2061_raw_progress_mtime_failure_is_replayable_evidence(tmp_path: Path) -> None:
    reports: list[tuple[str, object, bool, dict[str, object]]] = []

    info = file_has_recent_raw_owner_progress(
        tmp_path,
        tmp_path / "sample.bin",
        global_raw_file_id=lambda _path: "fid",
        accumulator_store_cls=_StoreWithMissingMtime,
        queue_now=lambda: 100.0,
        raw_stage_progress_recent=lambda *_args, **_kwargs: False,
        report=lambda stage, exc=None, *, fatal=False, extra=None: reports.append((stage, exc, fatal, extra or {})),
    )

    assert info["has_accumulator"] is True
    assert info["recent"] is False
    assert info["age"] is None
    assert info["mtime_unavailable"]["raw_progress_mtime_reason"] == "raw_progress_mtime_stat_failed"
    report = next(item for item in reports if item[0] == "queue_raw_owner_progress_mtime_unavailable")
    assert report[2] is False
    assert report[3]["raw_progress_mtime_available"] is False
    assert report[3]["error_type"] == "FileNotFoundError"


def test_stage2061_worker_lifecycle_missing_rejections_is_valid_empty_not_exception_default() -> None:
    boundary = SchedulerIsolationBoundary(scheduler_id="stage2061")

    record = boundary.transition(WorkerLifecycleEvent("worker-1", "queue-1", "new", "queued"))

    assert record["event_type"] == "worker_lifecycle"
    assert record["event"]["queue_id"] == "queue-1"
    assert "input_rejections" not in record

    source = read_python_file(Path("Virus_Scan/scheduler/workers/lifecycle_boundary.py"))
    assert "except KeyError:" not in source
