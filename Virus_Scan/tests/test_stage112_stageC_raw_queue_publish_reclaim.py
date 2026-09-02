import json
from pathlib import Path

import pytest

from Virus_Scan.scheduler.api.contracts import QueueIdentityScanError, RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.queue.raw_queue_directory import enqueue_guard
from Virus_Scan.scheduler.queue.raw_queue_identity import existing_identities
from Virus_Scan.scheduler.ownership.raw_queue_publish import RawQueuePublishDependencies, publish_raw_stage_job
from Virus_Scan.scheduler.queue.raw_queue_duplicates import duplicate_live_guard
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockAcquireDecision, IdentityLockReleaseDecision


def _raw_job(path="x.bin"):
    return {
        "job_type": "raw_stage",
        "file": path,
        "file_id": "fid-stage112",
        "collector": "identity",
        "seq": 7,
        "attempt": 0,
    }


def test_queue_enqueue_guard_fails_closed_when_identity_scan_breaks(tmp_path):
    calls = []

    assert enqueue_guard(
        tmp_path,
        _raw_job(),
        identity="raw:fid:identity:7:attempt:0",
        job_identity=lambda job, source_name=None: "raw:fid:identity:7:attempt:0",
        existing_identities=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("scan failed")),
        record_suppressed=lambda where, exc: calls.append((where, type(exc).__name__)),
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    ) is False
    assert any(where == "queue_enqueue_guard_failed_closed" for where, _ in calls)


def test_global_raw_publish_job_blocks_when_duplicate_guard_errors(tmp_path):
    calls = []

    deps = RawQueuePublishDependencies(
        global_raw_dirs=lambda queue_dir: (Path(queue_dir) / "pending", Path(queue_dir) / "active", Path(queue_dir) / "done", Path(queue_dir) / "failed", Path(queue_dir) / "accum", Path(queue_dir) / "locks"),
        global_raw_file_id=lambda path: "fid-stage112",
        raw_queue_live_count=lambda queue_dir: 0,
        runtime_value=lambda key, default=None: default,
        runtime_int=lambda key, default=0: default,
        umige_retry_max=lambda stage: 1,
        job_identity=lambda job, source_name=None: "raw:fid:identity:7:attempt:0",
        acquire_identity_lock_decision=lambda queue_dir, ident: IdentityLockAcquireDecision(True, tmp_path / "lock", "process_queue_identity_lock_acquired"),
        release_identity_lock_decision=lambda lock: IdentityLockReleaseDecision(True, "process_queue_identity_lock_released"),
        enqueue_guard=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("guard exploded")),
        write_json_durable=lambda *a, **k: True,
        identity_index_invalidate=lambda queue_dir: None,
        hybrid_queue_state_delta=lambda *a, **k: None,
        safe_unlink=lambda *a, **k: True,
        record_suppressed=lambda where, exc: calls.append((where, type(exc).__name__)),
    )
    assert publish_raw_stage_job(tmp_path, _raw_job(), deps).published is False
    assert any(where == "raw_publish_enqueue_guard_failed_closed" for where, _ in calls)
    pending = tmp_path / "pending"
    assert not pending.exists() or not list(pending.glob("*.json"))


def test_queue_existing_identities_strict_raises_instead_of_partial_success(tmp_path):
    calls = []

    with pytest.raises(QueueIdentityScanError):
        existing_identities(
            tmp_path,
            strict=True,
            job_dirs=lambda q: (_ for _ in ()).throw(OSError("list failed")),
            quarantine_dir=lambda q: Path(q) / "quarantine",
            file_results_dir=lambda q: Path(q) / "results",
            safe_listdir=lambda d: [],
            is_job_json_name=lambda name: str(name).endswith(".json"),
            read_json=lambda path, default=None: {},
            job_identity=lambda job, source_name=None: "raw:fid:identity:7:attempt:0",
            identity_index_get=lambda *a, **k: None,
            identity_index_set=lambda *a, **k: None,
            log_error=lambda msg: None,
            report=lambda where, exc, **kw: calls.append((where, type(exc).__name__)),
            raw_report=lambda where, exc: calls.append((where, type(exc).__name__)),
        )
    assert any(where == "queue_existing_identity_scan_failed" for where, _ in calls)


def test_queue_duplicate_live_guard_fails_closed_on_scan_error(tmp_path):
    calls = []
    claim = tmp_path / "active" / "job.json"
    claim.parent.mkdir(parents=True)
    claim.write_text(json.dumps(_raw_job()), encoding="utf-8")

    assert duplicate_live_guard(
        tmp_path,
        claim,
        _raw_job(),
        job_identity=lambda job, source_name=None: "raw:fid:identity:7:attempt:0",
        job_dirs=lambda q: (_ for _ in ()).throw(OSError("dirs unavailable")),
        safe_listdir=lambda d: [],
        is_job_json_name=lambda name: str(name).endswith(".json"),
        read_json=lambda path, default=None: {},
        merge_claim_meta=lambda claim_path, job=None: dict(job or {}),
        quarantine_job=lambda *a, **k: True,
        report=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal"))),
    ) is False
    assert ("queue_duplicate_live_guard_failed_closed", "OSError", True) in calls
