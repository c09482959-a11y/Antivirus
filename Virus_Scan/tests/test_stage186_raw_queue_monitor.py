import json
from pathlib import Path

from Virus_Scan.scheduler.workers.process_liveness import check_process_queue_worker_liveness
from Virus_Scan.scheduler.evidence.raw_queue_monitor import (
    queue_io_pressure_sample,
    queue_pressure_flags,
    queue_progress_counts_global,
)


def test_queue_pressure_flags_distinguishes_metadata_latency():
    sample = queue_pressure_flags({"pressure": True, "reason": "queue_latency"})
    assert sample["pressure"] is False
    assert sample["metadata_latency"] is True
    assert sample["actual_disk_io_pressure"] is False
    assert sample["reason"] == "queue_metadata_latency"


def test_queue_progress_counts_classifies_raw_payload(tmp_path):
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    for directory in (pending, active, done, failed):
        directory.mkdir()
    (pending / "file_1.json").write_text('{"job_type":"file"}')
    (active / "raw_1.json").write_text('{"job_type":"file"}')
    (done / "abc.json").write_text('{"job_type":"raw_stage"}')

    reports = []
    counts = queue_progress_counts_global(
        tmp_path,
        ensure_dirs=lambda _: None,
        queue_job_dirs=lambda _: (pending, active, done, failed),
        safe_queue_listdir=lambda directory: sorted(p.name for p in Path(directory).iterdir()),
        is_job_json_name=lambda name: str(name).endswith(".json"),
        read_json_file=lambda path, default=None: json.loads(Path(path).read_text()),
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
    )
    assert counts["file_pending"] == 1
    assert counts["raw_active"] == 1
    assert counts["raw_done"] == 1
    assert reports == []


def test_queue_io_pressure_reports_queue_list_failures(tmp_path):
    reports = []

    def listdir(path):
        if str(path).endswith("active"):
            raise OSError("denied")
        return []

    sample = queue_io_pressure_sample(
        tmp_path,
        safe_queue_listdir=listdir,
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
        psutil_module=None,
        environ={},
        sleep=lambda _: None,
        time_fn=lambda: 1.0,
    )
    assert sample["queue_files"] == 0
    assert any(args[0] == "io_pressure_queue_list_failed" for args, _ in reports)
    assert any(args[0] == "io_pressure_psutil_probe_failed" for args, _ in reports)


def test_pid_is_alive_rejects_invalid_pid_without_exception():
    reports = []
    result = check_process_queue_worker_liveness("not-an-int", record_suppressed=lambda *args, **kwargs: reports.append((args, kwargs)))
    assert result.alive is False
    assert result.reason == "pid_parse_failed"
    assert reports and reports[0][0][0] == "process_queue_pid_liveness_probe_failed"
