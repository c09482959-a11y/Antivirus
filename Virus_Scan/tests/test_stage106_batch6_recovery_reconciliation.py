import json


import Virus_Scan.scheduler.queue.claim as pqe
import Virus_Scan.scheduler.queue.feed_marker as pqa
import Virus_Scan.scheduler.queue.orphan_recovery as pqr


def test_feed_complete_marker_success_uses_text_readback(tmp_path):
    q = tmp_path / "q"
    pqe._ensure_process_queue_dirs(q)
    assert pqa.mark_process_queue_feed_complete(q) is True
    marker = q / "feed_complete.marker"
    assert marker.exists()
    assert pqa.process_queue_feed_is_complete(q) is True
    assert not list(q.rglob("*.tmp"))


def test_reclaim_annotation_failure_does_not_leave_stale_pending(tmp_path):
    q = tmp_path / "q"
    pqe._ensure_process_queue_dirs(q)
    pending, active, done, failed = pqe._queue_job_dirs(q)
    pending.mkdir(parents=True, exist_ok=True)

    dst = pending / "reclaim01_worker_1_00000000_00000000.json"
    stale = {
        "job_type": "file",
        "file": str(tmp_path / "sample.bin"),
        "queue_info": {"worker_pid": 123, "heartbeat_time": 1.0, "progress_marker": "active"},
    }
    dst.write_text(json.dumps(stale), encoding="utf-8")

    ok = pqr._publish_reclaimed_pending_job(
        q,
        dst,
        {
            "job_type": "file",
            "file": stale["file"],
            "attempt": 1,
            "reclaimed_from_active": True,
            "queue_info": {"retry_pending_active": True, "retry_pending_reason": "requeued_after_stall"},
            "queue_failure": True,
        },
        source_path=active / "worker_1_00000000_00000000.json",
    )
    assert ok is False
    assert not dst.exists(), "stale pending copy must not survive failed reclaim annotation"
    quarantine = q / "quarantine"
    assert quarantine.exists()
    quarantined = list(quarantine.glob("*.json"))
    assert quarantined, "failed annotation should quarantine rather than resurrect stale state"
    data = json.loads(quarantined[0].read_text(encoding="utf-8"))
    assert data.get("queue_failure") is True
    assert data.get("failure_info", {}).get("unsafe_to_continue") is True


def test_reclaim_annotation_success_requires_retry_metadata(tmp_path):
    q = tmp_path / "q"
    pqe._ensure_process_queue_dirs(q)
    pending, active, done, failed = pqe._queue_job_dirs(q)
    dst = pending / "reclaim01_worker_1_00000000_00000000.json"

    ok = pqr._publish_reclaimed_pending_job(
        q,
        dst,
        {
            "job_type": "file",
            "file": str(tmp_path / "sample.bin"),
            "attempt": 1,
            "reclaimed_from_active": True,
            "queue_info": {},
        },
    )
    assert ok is False
    assert not dst.exists()
