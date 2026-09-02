import json
from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_failed_diagnostics import repair_failed_queue_job_diagnostics


def test_repair_failed_queue_job_diagnostics_synthesizes_missing_failure_info(tmp_path):
    q = tmp_path
    failed = q / "failed"
    failed.mkdir(parents=True)
    job = failed / "job.json"
    job.write_text(json.dumps({"attempt": 2, "queue_info": {"worker_pid": 123}}), encoding="utf-8")
    suppressed = []

    repaired = repair_failed_queue_job_diagnostics(
        q,
        queue_job_dirs=lambda qd: (qd / "pending", qd / "active", qd / "done", qd / "failed"),
        safe_queue_listdir=lambda d: [p.name for p in d.iterdir()],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json_file=lambda path, default=None: json.loads(path.read_text(encoding="utf-8")),
        default_failure_info=lambda **kw: kw,
        make_json_safe=lambda value: value,
        queue_safe_unlink=lambda path, **kw: False,
        record_scheduler_suppressed=lambda ctx, exc: suppressed.append((ctx, type(exc).__name__)),
        log_error=lambda msg: suppressed.append(("log_error", msg)),
    )

    data = json.loads(job.read_text(encoding="utf-8"))
    assert repaired == 1
    assert data["queue_failure"] is True
    assert data["failure_info"]["stage"] == "queue_failed_without_original_diagnostics"
    assert data["failure_info"]["worker_pid"] == 123
    assert suppressed == []


def test_repair_failed_queue_job_diagnostics_uses_reclaim_history(tmp_path):
    q = tmp_path
    failed = q / "failed"
    failed.mkdir(parents=True)
    job = failed / "job.json"
    job.write_text(json.dumps({"queue_reclaim_history": [{"stage": "stale_claim", "error": "expired"}]}), encoding="utf-8")

    repaired = repair_failed_queue_job_diagnostics(
        q,
        queue_job_dirs=lambda qd: (qd / "pending", qd / "active", qd / "done", qd / "failed"),
        safe_queue_listdir=lambda d: [p.name for p in d.iterdir()],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json_file=lambda path, default=None: json.loads(path.read_text(encoding="utf-8")),
        default_failure_info=lambda **kw: kw,
        make_json_safe=lambda value: value,
        queue_safe_unlink=lambda path, **kw: False,
        record_scheduler_suppressed=lambda ctx, exc: None,
        log_error=lambda msg: None,
    )

    data = json.loads(job.read_text(encoding="utf-8"))
    assert repaired == 1
    assert data["failure_info"]["stage"] == "stale_claim"
    assert data["failure_info"]["exception_type"] == "QueueReclaimFailure"
