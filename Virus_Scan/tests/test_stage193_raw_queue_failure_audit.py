import json
from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_failure_audit import (
    collect_failed_queue_report,
    summarize_failed_queue_report,
)


def _job_dirs(root):
    paths = tuple(Path(root) / name for name in ("pending", "active", "done", "failed"))
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)
    return paths


def test_collect_failed_queue_report_synthesizes_missing_failure_info(tmp_path):
    failed = _job_dirs(tmp_path)[3]
    (failed / "001.json").write_text(json.dumps({"file": "sample.bin", "queue_info": {"worker_pid": 123}}), encoding="utf-8")

    report = collect_failed_queue_report(
        tmp_path,
        queue_job_dirs=_job_dirs,
        safe_queue_listdir=lambda p: sorted(x.name for x in Path(p).iterdir()),
        is_job_json_name=lambda name: str(name).endswith(".json"),
        read_json_file=lambda p, default=None: json.loads(Path(p).read_text(encoding="utf-8")),
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
        log_error=lambda msg: None,
    )

    assert len(report) == 1
    assert report[0]["file"] == "sample.bin"
    assert report[0]["stage"] == "failed_without_diagnostics"
    assert report[0]["worker_pid"] == 123


def test_summarize_failed_queue_report_is_deterministic():
    report = [
        {"job_type": "file", "stage": "a", "exception_type": "E", "error": "bad"},
        {"job_type": "file", "stage": "a", "exception_type": "E", "error": "bad"},
        {"job_type": "raw", "stage": "b", "exception_type": "F", "error": "worse"},
    ]
    summary = summarize_failed_queue_report(report)
    assert summary[0][0] == ("file", "a", "E", "bad")
    assert summary[0][1] == 2
