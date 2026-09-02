import os
import time
from pathlib import Path


from Virus_Scan.scheduler.runtime.queue_json import _queue_cleanup_orphan_json_temps
from Virus_Scan.scheduler.queue.raw_queue_cleanup import cleanup_diagnostic_tmp_files
from Virus_Scan.scheduler.queue.issue_reporting import record_raw_queue_issue
from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot, record_suppressed_failure


def test_suppressed_failure_records_forensic_context():
    clear_failure_records()
    try:
        raise RuntimeError("stage103 synthetic suppressed failure")
    except RuntimeError as exc:
        tag = record_suppressed_failure("stage103_unit", exc, domain="scheduler", tags=[])

    snap = failure_snapshot()["records"]
    assert tag.startswith("failure_scheduler_stage103_unit")
    assert len(snap) == 1
    rec = snap[0]
    assert rec["suppressed"] is True
    assert rec["fingerprint"]
    assert rec["correlation_id"]
    assert "RuntimeError" in rec["trace_tail"]
    assert "stage103 synthetic suppressed failure" in rec["trace_tail"]


def test_failure_snapshot_order_is_deterministic():
    clear_failure_records()
    record_suppressed_failure("zeta", ValueError("z"), domain="runtime")
    record_suppressed_failure("alpha", ValueError("a"), domain="runtime")
    first = [(r["domain"], r["where"], r["error_type"]) for r in failure_snapshot()["records"]]
    second = [(r["domain"], r["where"], r["error_type"]) for r in failure_snapshot()["records"]]
    assert first == second == sorted(first)


def test_queue_cleanup_orphan_json_temps_is_deterministic(tmp_path):

    target = tmp_path / "job.json"
    names = ["job.json.tmp.z", "job.json.tmp.a", "job.json.tmp.m"]
    for name in names:
        p = tmp_path / name
        p.write_text("{}", encoding="utf-8")
        old = time.time() - 1000
        os.utime(p, (old, old))
    removed = _queue_cleanup_orphan_json_temps(target, max_remove=2, min_age_sec=1)
    assert removed == 2
    remaining = sorted(p.name for p in tmp_path.iterdir())
    # Sorted cleanup should remove a before m before z when capped.
    assert remaining == ["job.json.tmp.z"]


def test_raw_cleanup_records_specific_cleanup_failure(tmp_path):

    clear_failure_records()
    d = tmp_path / "queue" / "failures"
    d.mkdir(parents=True)
    stale = d / "old.tmp"
    stale.write_text("x", encoding="utf-8")
    old = time.time() - 1000
    os.utime(stale, (old, old))

    def denied_unlink(*args, **kwargs):
        raise OSError("unlink denied")

    cleanup_diagnostic_tmp_files(
        tmp_path / "queue",
        failure_diagnostics_dir=lambda queue_dir: d,
        safe_listdir=lambda path: os.listdir(path),
        safe_unlink=denied_unlink,
        report=record_raw_queue_issue,
        max_age_sec=1,
    )

    records = failure_snapshot()["records"]
    assert records
    assert any(r["where"] == "queue_diagnostic_tmp_cleanup_failed" for r in records)
    assert all(r["where"] != "suppressed_exception" for r in records)
