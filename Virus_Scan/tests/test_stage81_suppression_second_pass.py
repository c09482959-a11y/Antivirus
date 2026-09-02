from pathlib import Path
import json


import Virus_Scan.scheduler.queue.claim as pqe
import Virus_Scan.scheduler.queue.orphan_recovery as pqr
import Virus_Scan.scheduler.queue.process_queue_finalization as pqf
import Virus_Scan.scheduler.queue.feed_marker as pqfm

def test_feed_complete_marker_does_not_publish_when_queue_directory_is_unavailable(tmp_path):
    q = tmp_path / "q"
    q.write_text("not a directory", encoding="utf-8")

    ok = pqfm.mark_process_queue_feed_complete(q)
    assert ok is False
    assert pqfm.process_queue_feed_is_complete(q) is False
    assert not list(q.rglob("*.tmp"))


def test_feed_complete_marker_reports_atomic_replace_failure(tmp_path):
    q = tmp_path / "q"
    pqe._ensure_process_queue_dirs(q)

    (q / "feed_complete.marker").mkdir()
    ok = pqfm.mark_process_queue_feed_complete(q)
    assert ok is False
    assert pqfm.process_queue_feed_is_complete(q) is False
    assert not list(q.rglob("*.tmp"))


def test_feed_complete_marker_rejects_invalid_content(tmp_path):
    q = tmp_path / "q"
    q.mkdir()
    (q / "feed_complete.marker").write_text("not-a-marker", encoding="utf-8")

    assert pqfm.process_queue_feed_is_complete(q) is False


def test_finish_process_queue_job_returns_false_when_terminal_move_fails(tmp_path):
    q = tmp_path / "q"
    pqe._ensure_process_queue_dirs(q)
    pending, active, done, failed = pqe._queue_job_dirs(q)
    claim = active / "worker_1_job.json"
    claim.write_text(json.dumps({"job_type":"file", "file":"x"}), encoding="utf-8")
    done.rmdir()
    done.write_text("terminal directory unavailable", encoding="utf-8")

    ok = pqf._finish_process_queue_job(q, claim, ok=True, job={"job_type":"file", "file":"x"})
    assert ok is False
    assert claim.exists()
    assert not (done / claim.name).exists()
