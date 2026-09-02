from pathlib import Path

def _unlink_and_return_true(path, **kwargs):
    Path(path).unlink(**kwargs)
    return True

from Virus_Scan.scheduler.ownership.raw_queue_publish import RawQueuePublishDependencies, publish_raw_stage_job
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision, IdentityLockReleaseDecision


def test_raw_stage_publish_uses_canonical_snapshot_without_mutating_caller_job(tmp_path):
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    accum = tmp_path / "accum"
    locks = tmp_path / "locks"
    for path in (pending, active, done, failed, accum, locks):
        path.mkdir()

    written = {}
    released = []
    suppressed = []

    def write_json_durable(tmp, final, payload, **_kwargs):
        written["payload"] = dict(payload)
        written["tmp"] = Path(tmp)
        written["final"] = Path(final)
        Path(tmp).write_text("{}", encoding="utf-8")
        Path(tmp).replace(final)
        return True

    deps = RawQueuePublishDependencies(
        global_raw_dirs=lambda _queue_dir: (pending, active, done, failed, accum, locks),
        global_raw_file_id=lambda file_path: "fid-" + Path(str(file_path)).name,
        raw_queue_live_count=lambda _queue_dir: 0,
        runtime_value=lambda _key, default: default,
        runtime_int=lambda _key, default: default,
        umige_retry_max=lambda _key: 1,
        job_identity=lambda job, _name=None: f"raw:{job['file_id']}:{job.get('collector','raw')}:{job.get('seq',0)}:{job.get('attempt',0)}",
        acquire_identity_lock_decision=lambda _queue_dir, identity: IdentityLockAcquireDecision(True, tmp_path / (identity.replace(':', '_') + ".lock"), "process_queue_identity_lock_acquired"),
        release_identity_lock_decision=lambda lock: released.append(lock) or IdentityLockReleaseDecision(True, "process_queue_identity_lock_released"),
        enqueue_guard=lambda *_args, **_kwargs: True,
        write_json_durable=write_json_durable,
        identity_index_invalidate=lambda _queue_dir: None,
        hybrid_queue_state_delta=lambda _queue_dir, **_delta: None,
        safe_unlink=lambda path, **_kwargs: _unlink_and_return_true(path, missing_ok=True),
        record_suppressed=lambda code, exc, **_kwargs: suppressed.append((code, type(exc).__name__)),
    )

    caller_job = {"file": "sample.bin", "collector": "strings", "seq": 7}
    original = dict(caller_job)

    assert publish_raw_stage_job(tmp_path, caller_job, deps).published is True

    assert caller_job == original
    assert written["payload"]["job_type"] == "raw_stage"
    assert written["payload"]["file_id"] == "fid-sample.bin"
    assert written["payload"]["seq"] == 7
    assert written["payload"]["attempt"] == 0
    assert written["payload"]["max_retries"] == 1
    assert written["final"].exists()
    assert released
    assert suppressed == []
