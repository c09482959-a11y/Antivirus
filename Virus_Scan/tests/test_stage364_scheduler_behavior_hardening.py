from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from types import SimpleNamespace

from Virus_Scan.scheduler.queue.snapshots import QueueBehaviorSnapshot, QueuePhaseLedger
from Virus_Scan.scheduler.queue.publication_state import QueuePublicationState, QueueRunFinalizationState, _result_publication_file_identity
from Virus_Scan.scheduler.queue.recovery_contracts import QueueRecoveryDecision, QueueWorkerFailureAccounting
from Virus_Scan.scheduler.queue.recovery_decisions import (
    classify_recovery_decision,
    _record_worker_failure_accounting,
)
from Virus_Scan.scheduler.queue.phase_validation import (
    ResultPublicationValidationRequest,
    _validate_queue_integrity,
    _validate_recovery_decision_batch,
    _validate_terminal_job_accounting,
    validate_result_publication,
)
from Virus_Scan.scheduler.queue.phase_ledger import (
    _record_queue_snapshot,
    _dispatch_ready_jobs,
    _finalize_queue_run,
    _apply_recovery_decisions,
    _record_result_publication,
    _validate_worker_lifecycle_cleanup,
    _claim_ready_jobs,
    _enqueue_queue_jobs,
    _finalize_queue_run_state,
)
from Virus_Scan.scheduler.replay.replay_validator import (
    normalize_scheduler_replay_results,
    assert_scheduler_replay_equivalent,
)
from Virus_Scan.scheduler.queue.scheduler_audit import (
    _build_scheduler_behavior_hardening_report,
    _build_scheduler_behavior_audit,
)
from Virus_Scan.core.paths import _queue_file_identity_for_path

rq = SimpleNamespace(
    QueueBehaviorSnapshot=QueueBehaviorSnapshot,
    QueuePhaseLedger=QueuePhaseLedger,
    QueuePublicationState=QueuePublicationState,
    QueueRecoveryDecision=QueueRecoveryDecision,
    QueueRunFinalizationState=QueueRunFinalizationState,
    QueueWorkerFailureAccounting=QueueWorkerFailureAccounting,
    _result_publication_file_identity=_result_publication_file_identity,
    classify_recovery_decision=classify_recovery_decision,
    _record_worker_failure_accounting=_record_worker_failure_accounting,
    _validate_queue_integrity=_validate_queue_integrity,
    validate_result_publication=validate_result_publication,
    _validate_recovery_decision_batch=_validate_recovery_decision_batch,
    _validate_terminal_job_accounting=_validate_terminal_job_accounting,
    _record_queue_snapshot=_record_queue_snapshot,
    _dispatch_ready_jobs=_dispatch_ready_jobs,
    _finalize_queue_run=_finalize_queue_run,
    _apply_recovery_decisions=_apply_recovery_decisions,
    _record_result_publication=_record_result_publication,
    _validate_worker_lifecycle_cleanup=_validate_worker_lifecycle_cleanup,
    _claim_ready_jobs=_claim_ready_jobs,
    _enqueue_queue_jobs=_enqueue_queue_jobs,
    _finalize_queue_run_state=_finalize_queue_run_state,
    normalize_scheduler_replay_results=normalize_scheduler_replay_results,
    assert_scheduler_replay_equivalent=assert_scheduler_replay_equivalent,
    _build_scheduler_behavior_hardening_report=_build_scheduler_behavior_hardening_report,
    _build_scheduler_behavior_audit=_build_scheduler_behavior_audit,
    _queue_file_identity_for_path=_queue_file_identity_for_path,
)


def _queue_dirs(root: Path) -> None:
    for name in ("pending", "active", "done", "failed", "quarantine"):
        (root / name).mkdir(parents=True, exist_ok=True)


def test_stage364_duplicate_file_publication_is_rejected_without_archive_child_identity(tmp_path: Path) -> None:
    sample = tmp_path / "same.bin"
    sample.write_bytes(b"payload")
    published_file_identity = rq._result_publication_file_identity({"job_id": "job-a", "file": str(sample)})

    with pytest.raises(RuntimeError, match="duplicate scheduler file result publication"):
        rq.validate_result_publication(ResultPublicationValidationRequest(
            {"job_id": "job-b", "file": str(sample)},
            {"job-b"},
            {"job-b"},
            set(),
            worker_id="worker-1",
            published_file_identities={published_file_identity},
        ))


def test_stage364_archive_child_identity_allows_same_container_file_publication(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(b"PK\x03\x04")
    first = rq._result_publication_file_identity(
        {"job_id": "job-a", "file": str(archive), "archive_child_identity": "a.bin"}
    )

    identity = rq.validate_result_publication(ResultPublicationValidationRequest(
        {"job_id": "job-b", "file": str(archive), "archive_child_identity": "b.bin"},
        {"job-b"},
        {"job-b"},
        set(),
        worker_id="worker-1",
        published_file_identities={first},
    ))

    assert identity == "job-b"


def test_stage364_worker_timeout_accounting_is_immutable_and_explicit(tmp_path: Path) -> None:
    sample = tmp_path / "timeout.bin"
    sample.write_bytes(b"x")

    accounting = rq._record_worker_failure_accounting(
        {"job_id": "job-timeout", "file": str(sample), "attempt": 2, "max_attempts": 2},
        {"worker_id": "worker-timeout", "source_event": "kill_timeout"},
        "timeout waiting for worker result",
    )

    assert accounting.worker_id == "worker-timeout"
    assert accounting.job_id == "job-timeout"
    assert accounting.file_path == str(sample)
    assert accounting.final_scheduler_action == "fail"
    assert accounting.failed is True
    assert accounting.requeued is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        accounting.failed = False  # type: ignore[misc]


def test_stage364_worker_failure_accounting_rejects_unaccounted_final_action() -> None:
    record = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-1",
        file_path="/tmp/sample.bin",
        failure_reason="worker killed",
        requeued=False,
        failed=False,
        attempt_count=0,
        final_scheduler_action="fail",
    )

    with pytest.raises(RuntimeError, match="must choose requeue or fail exactly once"):
        record.assert_valid()


def test_stage364_worker_lifecycle_cleanup_rejects_live_workers(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)

    with pytest.raises(RuntimeError, match="live child workers"):
        rq._validate_worker_lifecycle_cleanup(tmp_path, [], live_child_workers=["worker-9"])


def test_stage364_worker_lifecycle_cleanup_rejects_pending_queue_files(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    pending = tmp_path / "pending" / "job.json"
    pending.write_text(json.dumps({"file": str(tmp_path / "sample.bin")}), encoding="utf-8")

    with pytest.raises(RuntimeError, match="pending queue files"):
        rq._validate_worker_lifecycle_cleanup(tmp_path, [], pending_queue_files=[pending])


def test_stage364_worker_lifecycle_cleanup_accepts_accounted_final_state(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    failed_file = tmp_path / "failed" / "job.json"
    failed_file.write_text(json.dumps({"file": str(tmp_path / "sample.bin")}), encoding="utf-8")
    record = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-1",
        file_path=str(tmp_path / "sample.bin"),
        failure_reason="timeout",
        requeued=False,
        failed=True,
        attempt_count=2,
        final_scheduler_action="fail",
    )

    snapshot = rq._validate_worker_lifecycle_cleanup(tmp_path, [record])

    assert snapshot.phase == "finalize"
    assert snapshot.failed == 1
