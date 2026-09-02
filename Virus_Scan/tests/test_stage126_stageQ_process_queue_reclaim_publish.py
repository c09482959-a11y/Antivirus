import json
import os
from pathlib import Path

def _append_and_return_true(target, value):
    target.append(value)
    return True

from Virus_Scan.scheduler.queue import claim as pqe
from Virus_Scan.scheduler.queue import publish as pqp


def test_process_queue_runtime_install_surface_removed():
    assert not hasattr(pqe, "ProcessQueueRuntime")
    assert not hasattr(pqe, "bind_process_queue_state_runtime")


def test_write_process_queue_jobs_slice_guard_exception_fails_closed(tmp_path):
    queue_dir = tmp_path / "q"
    seen = []
    def failing_publish_attempt(*args, **kwargs):
        seen.append(kwargs["guard_failure_stage"])
        return 0, 0, 1

    cursor, enqueued, skipped = pqp._write_process_queue_jobs_slice(
        queue_dir,
        [(0, 0, tmp_path / "sample.bin", "generic")],
        0,
        1,
        set(),
        publish_attempt_func=failing_publish_attempt,
        record_suppressed=lambda where, exc, **kw: _append_and_return_true(seen, where),
    )

    assert cursor == 1
    assert enqueued == 0
    assert skipped == 0
    pending, *_ = pqp._queue_job_dirs(queue_dir)
    assert list(pending.glob("*.json")) == []
    assert "process_queue_slice_enqueue_guard_exception_failed_closed" in seen


def test_write_process_queue_jobs_slice_identity_lock_conflict_skips_duplicate(tmp_path):
    queue_dir = tmp_path / "q"
    f = tmp_path / "same.bin"
    job = {"file": str(f), "queue_file_id": pqp._queue_file_identity_for_path(f)}
    ident = pqp._queue_job_identity(job, None)
    decision = pqp._queue_acquire_identity_lock_decision(queue_dir, ident)
    assert decision.acquired is True
    assert decision.lock_path is not None and Path(decision.lock_path).exists()
    try:
        cursor, enqueued, skipped = pqp._write_process_queue_jobs_slice(
            queue_dir,
            [(0, 0, f, "generic")],
            0,
            1,
            {ident},
        )
        assert cursor == 1
        assert enqueued == 0
        assert skipped == 1
    finally:
        assert pqp._queue_release_identity_lock_decision(decision.lock_path).released is True


def test_write_process_queue_jobs_slice_publishes_semantic_job_and_releases_lock(tmp_path):
    queue_dir = tmp_path / "q"
    cursor, enqueued, skipped = pqp._write_process_queue_jobs_slice(
        queue_dir,
        [(0, 0, tmp_path / "ok.bin", "generic")],
        0,
        1,
        set(),
    )
    assert (cursor, enqueued, skipped) == (1, 1, 0)
    pending, *_ = pqp._queue_job_dirs(queue_dir)
    jobs = list(pending.glob("*.json"))
    assert len(jobs) == 1
    payload = json.loads(jobs[0].read_text())
    assert payload["file"].endswith("ok.bin")
    assert payload["queue_file_id"]
    assert not list((queue_dir / "identity_locks").glob("*.lock"))
