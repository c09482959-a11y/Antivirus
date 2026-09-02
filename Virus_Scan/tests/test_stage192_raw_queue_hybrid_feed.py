from pathlib import Path

from Virus_Scan.scheduler.evidence.raw_queue_degradation import record_raw_queue_issue
from Virus_Scan.scheduler.queue.feed_marker import queue_feed_complete_path
from Virus_Scan.scheduler.runtime.queue_filesystem_operations import queue_fs_backoff
from Virus_Scan.scheduler.replay.replay_snapshot import hybrid_queue_state_delta, hybrid_queue_state_get, hybrid_queue_state_set


def test_stage192_hybrid_state_owned_outside_raw_queue(tmp_path):
    calls = []
    report = lambda where, exc: calls.append((where, type(exc).__name__))

    hybrid_queue_state_set(tmp_path, {"raw_pending": 1})
    assert hybrid_queue_state_get(tmp_path) == {"raw_pending": 1}

    hybrid_queue_state_delta(tmp_path, report=report, raw_done=2, raw_pending=object())
    assert hybrid_queue_state_get(tmp_path) == {"raw_pending": 1}
    assert ("hybrid_queue_state_delta_invalid", "HybridQueueStateError") in calls


def test_stage192_hybrid_state_module_has_canonical_store(tmp_path):
    hybrid_queue_state_set(tmp_path, {"file_pending": 3})
    assert hybrid_queue_state_get(tmp_path) == {"file_pending": 3}


def test_stage192_feed_marker_and_backoff_policy(tmp_path):
    assert queue_feed_complete_path(tmp_path) == Path(tmp_path) / "feed_complete.marker"
    assert queue_fs_backoff(0, delay=0.1) == 0.1
    assert queue_fs_backoff(9, delay=0.1) == 0.5
