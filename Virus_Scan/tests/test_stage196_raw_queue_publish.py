from pathlib import Path

from Virus_Scan.scheduler.ownership.raw_queue_publish import RawQueuePublishDependencies, publish_raw_stage_job
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision, IdentityLockReleaseDecision


def _dirs(root):
    base = Path(root)
    dirs = tuple(base / name for name in ("pending", "active", "done", "failed", "accumulators", "locks"))
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def _deps(tmp_path, *, live_count=0, guard=True, writes=True):
    events = []
    def write_json(tmp, final, payload, *, log_context):
        if not writes:
            return False
        tmp.write_text("{}", encoding="utf-8")
        tmp.replace(final)
        events.append(("write", final.name, log_context))
        return True
    def acquire(_queue_dir, ident):
        events.append(("lock", ident))
        return IdentityLockAcquireDecision(True, tmp_path / "identity.lock", "process_queue_identity_lock_acquired")
    def release(lock):
        events.append(("release", Path(lock).name if lock else None))
        return IdentityLockReleaseDecision(True, "process_queue_identity_lock_released")
    deps = RawQueuePublishDependencies(
        global_raw_dirs=_dirs,
        global_raw_file_id=lambda file: "fid123",
        raw_queue_live_count=lambda queue_dir: live_count,
        runtime_value=lambda name, default=None: default,
        runtime_int=lambda name, default=0: default,
        umige_retry_max=lambda stage: 1,
        job_identity=lambda job, fallback=None: f"{job.get('file_id')}:{job.get('seq')}",
        acquire_identity_lock_decision=acquire,
        release_identity_lock_decision=release,
        enqueue_guard=lambda *args, **kwargs: guard,
        write_json_durable=write_json,
        identity_index_invalidate=lambda queue_dir: events.append(("invalidate", Path(queue_dir).name)),
        hybrid_queue_state_delta=lambda queue_dir, **delta: events.append(("delta", delta)),
        safe_unlink=lambda path, **kwargs: events.append(("unlink", Path(path).name)),
        record_suppressed=lambda where, exc: events.append(("suppressed", where)),
    )
    return deps, events


def test_publish_raw_stage_job_uses_deterministic_name_and_invalidates_index(tmp_path):
    deps, events = _deps(tmp_path)
    job = {"file": "sample.bin", "collector": "binary/context", "seq": 7}
    assert publish_raw_stage_job(tmp_path, job, deps).published is True
    pending = tmp_path / "pending"
    names = [p.name for p in pending.iterdir()]
    assert names == ["raw_fid123_000007_a00_binary_context.json"]
    assert ("invalidate", tmp_path.name) in events
    assert ("delta", {"raw_pending": 1}) in events


def test_publish_raw_stage_job_fails_closed_when_duplicate_guard_rejects(tmp_path):
    deps, _events = _deps(tmp_path, guard=False)
    job = {"file_id": "abc", "file": "sample.bin", "collector": "identity", "seq": 1}
    assert publish_raw_stage_job(tmp_path, job, deps).published is False
    assert not any((tmp_path / "pending").iterdir())
