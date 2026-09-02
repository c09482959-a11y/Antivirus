from pathlib import Path
import tempfile


from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload
from Virus_Scan.scheduler.queue import publish as pqp
from Virus_Scan.scheduler.queue import publish_durable as pqd
from Virus_Scan.scheduler.queue.raw_queue_accumulator import RawAccumulatorDependencies, RawAccumulatorStore
from Virus_Scan.scheduler.ownership.raw_queue_publish import RawQueuePublishDependencies, publish_raw_stage_job
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision, IdentityLockReleaseDecision

def test_worker_output_fast_fsync_failure_fails_closed(tmp_path):
    blocked_parent = tmp_path / 'worker-output-parent'
    blocked_parent.write_text('not a directory', encoding='utf-8')
    dst = blocked_parent / 'worker.json'
    assert write_worker_output_payload(str(dst), {'ok': True}) is False
    assert not dst.exists()
    assert not list(tmp_path.glob('*.tmp'))


def test_process_queue_enqueue_fsync_failure_does_not_publish(tmp_path):
    root = tmp_path / 'q'
    f = tmp_path / 'a.bin'
    f.write_bytes(b'x')
    def failed_publish(*_args, **_kwargs):
        return False, False, True

    pqp._write_process_queue_jobs(root, [str(f)], publish_attempt_func=failed_publish)
    pending = root / 'pending'
    assert not list(pending.glob('*.json')) if pending.exists() else True
    assert not list(pending.glob('*.tmp')) if pending.exists() else True


def test_process_queue_slice_fsync_failure_not_counted(tmp_path):
    root = tmp_path / 'q'
    f = tmp_path / 'a.bin'
    f.write_bytes(b'x')
    def failed_publish(*_args, **_kwargs):
        return False, False, True

    cursor, enqueued, skipped = pqp._write_process_queue_jobs_slice(
        root,
        [(0, 0, str(f), 'generic')],
        0,
        1,
        set(),
        publish_attempt_func=failed_publish,
    )
    assert enqueued == 0
    pending = root / 'pending'
    assert not list(pending.glob('*.json')) if pending.exists() else True


def test_raw_accumulator_durable_write_failure_fails_closed(tmp_path):
    dirs = tuple(tmp_path / name for name in ('raw_pending', 'raw_active', 'raw_done', 'raw_failed', 'accumulators', 'locks'))
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    deps = RawAccumulatorDependencies(
        global_raw_dirs=lambda queue_dir: dirs,
        read_json_file=lambda path, default=None, **kw: default if default is not None else {},
        write_json_durable=lambda *a, **k: False,
        ordered_unique_tags=lambda tags: list(dict.fromkeys(tags)),
        normalize_yara_hits=lambda hits: list(hits),
        record_scheduler_suppressed=lambda stage, exc: None,
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
    )
    store = RawAccumulatorStore(tmp_path, 'file1', deps)
    try:
        store.save({'a': 1})
    except RuntimeError:
        pass
    else:
        raise AssertionError('raw accumulator save succeeded after fsync failure')
    assert not list(tmp_path.rglob('*.json'))


def test_raw_publish_durable_write_failure_fails_closed(tmp_path):
    root = tmp_path / 'q'
    pending = root / 'raw_pending'
    dirs = tuple(root / name for name in ('raw_pending', 'raw_active', 'raw_done', 'raw_failed', 'accumulators', 'locks'))
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    raw_job = {'file_id': 'f', 'seq': 1, 'file': 'x'}
    deps = RawQueuePublishDependencies(
        global_raw_dirs=lambda queue_dir: dirs,
        global_raw_file_id=lambda file_path: 'f',
        raw_queue_live_count=lambda queue_dir: 0,
        runtime_value=lambda name, default=None: default,
        runtime_int=lambda name, default=0: default,
        umige_retry_max=lambda stage: 1,
        job_identity=lambda job, name=None: f"{job.get('file_id')}:{job.get('seq')}",
        acquire_identity_lock_decision=lambda queue_dir, ident: IdentityLockAcquireDecision(True, root / "identity.lock", "process_queue_identity_lock_acquired"),
        release_identity_lock_decision=lambda lock: IdentityLockReleaseDecision(True, "process_queue_identity_lock_released"),
        enqueue_guard=lambda *a, **k: True,
        write_json_durable=lambda *a, **k: False,
        identity_index_invalidate=lambda queue_dir: None,
        hybrid_queue_state_delta=lambda *a, **k: None,
        safe_unlink=lambda *a, **k: None,
        record_suppressed=lambda stage, exc: None,
    )
    assert publish_raw_stage_job(root, raw_job, deps).published is False
    pending = root / 'raw_pending'
    assert not list(pending.glob('*.json')) if pending.exists() else True
