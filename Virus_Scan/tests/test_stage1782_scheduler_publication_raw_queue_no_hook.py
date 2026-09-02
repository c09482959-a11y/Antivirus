from pathlib import Path

from Virus_Scan.scheduler.ownership.raw_queue_publish import (
    RawQueuePublishDependencies,
    publish_raw_stage_job,
)
from Virus_Scan.scheduler.runtime.queue_json_locks import QueueJsonReplaceLockOwner
from Virus_Scan.scheduler.workers.inmemory_result_publication import (
    publish_completed_inmemory_worker_result,
)
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision, IdentityLockReleaseDecision


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    fspath_calls = 0

    @classmethod
    def reset(cls):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.fspath_calls = 0

    @classmethod
    def total(cls):
        return (
            cls.str_calls
            + cls.repr_calls
            + cls.format_calls
            + cls.bool_calls
            + cls.iter_calls
            + cls.float_calls
            + cls.int_calls
            + cls.fspath_calls
        )

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute")

    def __fspath__(self):
        type(self).fspath_calls += 1
        raise RuntimeError("must not execute")


class FailingFuture:
    def __init__(self, error):
        self.error = error

    def result(self):
        raise self.error


class ResultQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


def raw_dirs(root):
    base = Path(root)
    dirs = tuple(base / name for name in ("pending", "active", "done", "failed", "accumulators", "locks"))
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
    return dirs


def test_stage1782_inmemory_result_publication_rejects_hostile_failure_evidence_without_hooks():
    HostileValue.reset()
    path = HostileValue()
    attempt = HostileValue()
    processed = HostileValue()
    max_jobs = HostileValue()
    worker_error = RuntimeError(HostileValue())
    constructor_error = RuntimeError(HostileValue())
    future = FailingFuture(worker_error)
    result_q = ResultQueue()
    worker_error_paths = []

    def broken_worker_error_result(path_arg, _exc):
        worker_error_paths.append(path_arg)
        raise constructor_error

    publication = publish_completed_inmemory_worker_result(
        future=future,
        active={future: {"job_id": 17, "path": path, "attempt": attempt}},
        result_q=result_q,
        max_jobs_per_worker=max_jobs,
        processed_jobs=processed,
        worker_error_result=broken_worker_error_result,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda _stage, _exc: None,
    )

    assert HostileValue.total() == 0
    assert worker_error_paths == [""]
    assert publication.worker_error_result_failed is True
    assert publication.processed_jobs == 1
    assert publication.stop_requested is False
    assert publication.path == ""
    published = result_q.items[0][3]
    integrity = published["scan_integrity"]
    assert integrity["worker_error_result_construction_failed"] is True
    assert integrity["worker_result_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert "scheduler diagnostic detail unavailable without caller hooks" in integrity["worker_failure_error"]


def test_stage1782_raw_queue_publish_sanitizes_hostile_job_identity_fields_before_publish(tmp_path):
    HostileValue.reset()
    events = []
    payloads = []

    def write_json(tmp, final, payload, *, log_context):
        payloads.append(payload)
        tmp.write_text("{}", encoding="utf-8")
        tmp.replace(final)
        events.append(("write", final.name, log_context))
        return True

    deps = RawQueuePublishDependencies(
        global_raw_dirs=raw_dirs,
        global_raw_file_id=lambda file_text: "fid_safe" if file_text == "" else "fid_unexpected",
        raw_queue_live_count=lambda _queue_dir: 0,
        runtime_value=lambda _name, default=None: default,
        runtime_int=lambda _name, default=0: default,
        umige_retry_max=lambda _stage: 1,
        job_identity=lambda job, _fallback=None: f"{job.get('file_id')}:{job.get('seq')}:{job.get('collector')}",
        acquire_identity_lock_decision=lambda _queue_dir, ident: events.append(("lock", ident)) or IdentityLockAcquireDecision(True, tmp_path / "lock", "process_queue_identity_lock_acquired"),
        release_identity_lock_decision=lambda _lock: events.append(("release", "lock")) or IdentityLockReleaseDecision(True, "process_queue_identity_lock_released"),
        enqueue_guard=lambda *_args, **_kwargs: True,
        write_json_durable=write_json,
        identity_index_invalidate=lambda _queue_dir: events.append(("invalidate", "queue")),
        hybrid_queue_state_delta=lambda _queue_dir, **delta: events.append(("delta", delta)),
        safe_unlink=lambda path, **_kwargs: events.append(("unlink", Path(path).name)),
        record_suppressed=lambda where, _exc: events.append(("suppressed", where)),
    )
    job = {
        "file": HostileValue(),
        "file_id": HostileValue(),
        "collector": HostileValue(),
        "seq": HostileValue(),
        "attempt": HostileValue(),
        "max_retries": HostileValue(),
    }

    assert publish_raw_stage_job(tmp_path, job, deps).published is True

    assert HostileValue.total() == 0
    assert [path.name for path in (tmp_path / "pending").iterdir()] == ["raw_fid_safe_000000_a00_raw.json"]
    assert payloads[0]["file"] == ""
    assert payloads[0]["file_id"] == "fid_safe"
    assert payloads[0]["collector"] == "raw"
    assert payloads[0]["seq"] == 0
    assert payloads[0]["attempt"] == 0
    assert payloads[0]["max_retries"] == 1
    suppressed = {event[1] for event in events if event[0] == "suppressed"}
    assert "raw_publish_file_rejected" in suppressed
    assert "raw_publish_file_id_rejected" in suppressed
    assert "raw_publish_seq_parse_failed" in suppressed
    assert "raw_publish_attempt_parse_failed" in suppressed
    assert "raw_publish_max_retries_parse_failed" in suppressed


def test_stage1782_queue_json_lock_owner_rejects_hostile_path_without_fspath_or_str(tmp_path):
    HostileValue.reset()
    owner = QueueJsonReplaceLockOwner()
    token = owner.acquire_for(HostileValue())
    try:
        assert token[0] == "unsupported_scheduler_queue_json_path:HostileValue"
    finally:
        owner.release_for(token)
    exact_token = owner.acquire_for(tmp_path / "queue.json")
    try:
        assert exact_token[0].endswith("queue.json")
    finally:
        owner.release_for(exact_token)
    assert HostileValue.total() == 0
