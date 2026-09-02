import inspect

from pathlib import Path

from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_deps
from Virus_Scan.scheduler.context import inmemory_raw_policy_dependencies as raw_policy
from Virus_Scan.scheduler.ownership.raw_queue_publish import RawQueuePublishDependencies, publish_raw_stage_job
from Virus_Scan.scheduler.runtime.worker_capacity import raw_collector_cap
from Virus_Scan.runtime.config_values import runtime_int
from Virus_Scan.scheduler.queue.raw_integrity import raw_integrity_degraded
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision, IdentityLockReleaseDecision


def test_stage117_raw_queue_surface_removed_after_canonical_owner_collapse():
    assert not Path(__file__).resolve().parents[1].joinpath("scheduler/raw_queue.py").exists()


def test_stage117_integrity_degraded_type_boundary_is_fail_closed():
    class BadIntegrity:
        def get(self, *args, **kwargs):
            raise TypeError('bad integrity object')
    assert raw_integrity_degraded(BadIntegrity()) is True


def test_stage117_raw_config_helpers_typed_fallback_records_policy_evidence():
    def bad_runtime_value(*a, **k):
        raise ValueError('bad config')

    calls = []

    def record_policy_issue(where, exc):
        calls.append((where, type(exc).__name__, str(exc)))

    assert raw_policy.raw_chunk_bytes(123, runtime_value_reader=bad_runtime_value, record_policy_issue=record_policy_issue) == 123
    assert raw_policy.raw_queue_max_chunks(7, runtime_value_reader=bad_runtime_value, record_policy_issue=record_policy_issue) == 7
    assert raw_policy.raw_queue_enabled(runtime_value_reader=bad_runtime_value, record_policy_issue=record_policy_issue) is False
    assert raw_policy.raw_queue_min_bytes(9, runtime_value_reader=bad_runtime_value, record_policy_issue=record_policy_issue) == 9
    assert raw_deps._raw_chunk_bytes is raw_policy.raw_chunk_bytes
    assert calls == [
        ('raw_queue_chunk_bytes_policy_issue', 'ValueError', 'bad config'),
        ('raw_queue_max_chunks_policy_issue', 'ValueError', 'bad config'),
        ('raw_queue_enabled_policy_issue', 'ValueError', 'bad config'),
        ('raw_queue_min_bytes_policy_issue', 'ValueError', 'bad config'),
    ]


def test_stage117_raw_publish_write_failure_records_and_fails_closed(tmp_path):
    calls = []
    deps = RawQueuePublishDependencies(
        global_raw_dirs=lambda q: (Path(q) / 'pending', Path(q) / 'active', Path(q) / 'done', Path(q) / 'failed', Path(q) / 'accum', Path(q) / 'locks'),
        global_raw_file_id=lambda path: 'fid-stage117',
        raw_queue_live_count=lambda q: 0,
        runtime_value=lambda key, default=None: default,
        runtime_int=lambda key, default=0: default,
        umige_retry_max=lambda stage: 1,
        job_identity=lambda job, source_name=None: 'raw:fid-stage117:identity:1:attempt:0',
        acquire_identity_lock_decision=lambda q, i: IdentityLockAcquireDecision(True, tmp_path / "identity.lock", "process_queue_identity_lock_acquired"),
        release_identity_lock_decision=lambda lock: IdentityLockReleaseDecision(True, "process_queue_identity_lock_released"),
        enqueue_guard=lambda *a, **k: True,
        write_json_durable=lambda *a, **k: (_ for _ in ()).throw(OSError('write denied')),
        identity_index_invalidate=lambda q: None,
        hybrid_queue_state_delta=lambda *a, **k: None,
        safe_unlink=lambda *a, **k: True,
        record_suppressed=lambda where, exc: calls.append((where, type(exc).__name__, str(exc))),
    )
    result = publish_raw_stage_job(str(tmp_path), {'file': str(tmp_path / 'x.bin'), 'collector': 'identity', 'seq': 1}, deps)
    assert result.published is False
    assert result.reason == 'raw_publish_write_failed_closed'
    assert any(where == 'raw_publish_write_failed_closed' and etype == 'OSError' for where, etype, _ in calls)


def test_stage117_raw_collector_cap_does_not_require_legacy_globals():
    for name in (
        'RAW_PER_FILE_ACTIVE_CAP', 'RAW_DECODE_CAP',
        'RAW_PAYLOAD_CAP', 'RAW_PE_API_CAP', 'RAW_BINARY_CONTEXT_CAP',
        'RAW_RENPY_CAP',
    ):
        assert not hasattr(raw_deps, name), name
    assert raw_collector_cap('identity', runtime_int=runtime_int) == runtime_int('RAW_PER_FILE_ACTIVE_CAP', 128)
    assert raw_collector_cap('yara_group', runtime_int=runtime_int) == runtime_int('RAW_PER_FILE_ACTIVE_CAP', 128)
