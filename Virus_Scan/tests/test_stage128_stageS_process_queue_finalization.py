import json
from pathlib import Path

def _append_and_return_true(target, value):
    target.append(value)
    return True

from Virus_Scan.scheduler.queue import claim as pqe
import Virus_Scan.scheduler.queue.orphan_recovery as pqr
import Virus_Scan.scheduler.queue.reclaim_publication as reclaim_publication
import Virus_Scan.scheduler.queue.process_queue_finalization as pqf
import Virus_Scan.scheduler.queue.feed_marker as pqfm
import Virus_Scan.scheduler.queue.dirs as pqdirs
import Virus_Scan.scheduler.queue.publish as pqp
import Virus_Scan.scheduler.queue.publish_durable as pqd


def _queue_dirs(q: Path):
    pending, active, done, failed = pqe._queue_job_dirs(q)
    for d in (pending, active, done, failed):
        d.mkdir(parents=True, exist_ok=True)
    return pending, active, done, failed


def test_ensure_process_queue_dirs_uses_owned_diagnostic_cleanup_not_globals(tmp_path):
    q = tmp_path / "q"
    seen = []
    assert pqdirs._ensure_process_queue_dirs(
        q,
        diagnostic_cleanup=lambda *a, **k: -1,
        record_suppressed=lambda where, exc, **kw: _append_and_return_true(seen, (where, kw)),
    ) is True

    assert any(where == "queue_ensure_dirs_diagnostic_cleanup_incomplete" for where, _ in seen)
    src = Path(pqdirs.__file__).read_text(encoding="utf-8")
    body = src.split("def _ensure_process_queue_dirs", 1)[1]
    assert '"_queue_cleanup_diagnostic_tmp_files" in globals()' not in body
    assert "def _queue_cleanup_diagnostic_tmp_files" not in src
    assert "process_queue_suppressed_exception" not in body


def test_finish_process_queue_job_move_failure_is_attributable_and_does_not_raise(tmp_path):
    q = tmp_path / "q"
    pending, active, done, failed = _queue_dirs(q)
    claim = active / "worker_1_000001.json"
    claim.write_text(json.dumps({"file": "a.bin", "queue_file_id": "id-a"}), encoding="utf-8")
    done.rmdir()
    done.write_text("terminal directory unavailable", encoding="utf-8")
    seen = []
    assert pqf._finish_process_queue_job(
        q,
        claim,
        ok=True,
        job={"file": "a.bin"},
        record_suppressed=lambda where, exc, **kw: _append_and_return_true(seen, (where, kw)),
    ) is False

    assert any(where == "queue_finish_failed" and meta.get("fatal") is True for where, meta in seen)


def test_feed_complete_probe_fails_closed_with_telemetry(tmp_path):
    seen = []
    assert pqfm.process_queue_feed_is_complete(
        tmp_path / "q",
        feed_complete_path=lambda queue_dir: (_ for _ in ()).throw(RuntimeError("path broken")),
        record_suppressed=lambda where, exc, **kw: _append_and_return_true(seen, (where, kw)),
    ) is False
    assert any(where == "queue_feed_complete_probe_failed_closed" for where, _ in seen)


def test_reclaim_annotation_failure_removes_pending_stale_job(tmp_path):
    q = tmp_path / "q"
    pending, active, done, failed = _queue_dirs(q)
    pending_job = pending / "reclaim01_000001.json"
    pending_job.write_text(json.dumps({"file": "stale.bin", "queue_info": {"worker_pid": 123}}), encoding="utf-8")
    (q / "quarantine").write_text("quarantine unavailable", encoding="utf-8")
    seen = []
    ok = pqr._publish_reclaimed_pending_job(
        q,
        pending_job,
        {"file": "stale.bin", "reclaimed_from_active": True, "queue_failure": True},
        source_path=active / "000001.json",
        record_suppressed=lambda where, exc, **kw: _append_and_return_true(seen, (where, kw)),
    )

    assert ok is False
    assert not pending_job.exists()
    assert any(where == "queue_reclaim_annotation_failed" for where, _ in seen)
    assert any(where == "queue_reclaim_annotation_quarantine_failed" for where, _ in seen)


def test_process_queue_engine_stage_s_removed_targeted_broad_handlers():
    src = Path(pqf.__file__).read_text(encoding="utf-8")
    finish_body = src.split("def _finish_process_queue_job", 1)[1]
    reclaim_src = Path(pqr.__file__).read_text(encoding="utf-8")
    reclaim_body = reclaim_src.split("def _reclaim_stale_process_queue_jobs", 1)[1]
    publish_src = Path(pqd.__file__).read_text(encoding="utf-8")
    write_body = publish_src.split("def _write_queue_job_json_durable", 1)[1]
    assert "except Exception" not in finish_body
    assert "process_queue_suppressed_exception" not in reclaim_body
    assert "except Exception" not in write_body
