import json
from dataclasses import replace
from pathlib import Path

from Virus_Scan.scheduler.context.inmemory_raw_dependency_factory import execute_inmemory_raw_stage_job
from Virus_Scan.scheduler.queue import raw_accumulator_store as ras


def test_raw_range_read_failure_becomes_degraded_stage_error(tmp_path):
    missing = tmp_path / "missing.bin"
    job = {
        "file": str(missing),
        "collector": "binary_context",
        "file_id": "fid",
        "seq": 1,
        "start": 0,
        "size": 128,
        "attempt": 0,
    }
    out = execute_inmemory_raw_stage_job(job)
    assert out.get("error")
    assert "scanner_failure" in out.get("tags", [])
    assert "scanner_degraded" in out.get("tags", [])
    assert "scan_incomplete" in out.get("tags", [])
    assert out.get("suspicious") is False


def test_raw_write_json_durable_removes_bad_final_on_verify_failure(tmp_path):
    tmp = tmp_path / "record.json.tmp"
    final = tmp_path / "record.json"
    payload = {"job_type": "raw_stage", "file": "x.bin", "file_id": "abc", "collector": "identity", "seq": 0}

    real_verify = ras.verify_persistent_json_file

    def verify(path, *args, **kwargs):
        if Path(path) == final:
            raise AssertionError("forced final mismatch")
        return real_verify(path, *args, **kwargs)

    deps = replace(
        ras.raw_json_dependencies(),
        verify_persistent_json_file=verify,
    )
    assert ras.write_raw_json_durable(tmp, final, payload, log_context="stage111_test", deps=deps) is False
    assert not final.exists()


def test_raw_write_json_durable_rejects_semantically_incomplete_payload(tmp_path):
    tmp = tmp_path / "bad.json.tmp"
    final = tmp_path / "bad.json"
    # queue_failure without failure_info is a Stage101+ semantic boundary violation.
    payload = {"job_type": "raw_stage", "file": "x.bin", "file_id": "abc", "collector": "identity", "seq": 0, "queue_failure": True}
    assert ras.write_raw_json_durable(tmp, final, payload, log_context="stage111_bad_semantics") is False
    assert not final.exists()


def test_raw_accumulator_lock_cleanup_failure_is_attributable(tmp_path):
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    calls = []
    deps = replace(
        ras.raw_accumulator_dependencies(),
        record_scheduler_suppressed=lambda where, exc: calls.append((where, type(exc).__name__)),
    )
    lock = ras.GlobalRawAccumLock(lock_dir, "x", deps=deps)
    with lock:
        # Make os.rmdir fail by putting a child inside the lock dir.  The fallback
        # rmtree should clean it, and the original cleanup anomaly must be recorded.
        (lock.path / "child").write_text("x", encoding="utf-8")
    assert not lock.path.exists()
    assert any(where == "raw_accumulator_lock_rmdir_failed" for where, _ in calls)
