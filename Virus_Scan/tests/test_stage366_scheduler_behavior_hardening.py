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


def test_stage366_publication_state_is_immutable_and_rejects_duplicate_job(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    state = rq.QueuePublicationState.empty()
    next_state = rq._record_result_publication(
        state,
        {"job_id": "job-1", "file": str(sample)},
        {"job-1"},
        {"job-1"},
        worker_id="worker-1",
    )

    assert state.job_identities == frozenset()
    assert next_state.job_identities == frozenset({"job-1"})
    with pytest.raises(dataclasses.FrozenInstanceError):
        next_state.job_identities = frozenset()  # type: ignore[misc]
    with pytest.raises(RuntimeError, match="duplicate scheduler result publication"):
        rq._record_result_publication(
            next_state,
            {"job_id": "job-1", "file": str(sample)},
            {"job-1"},
            {"job-1"},
            worker_id="worker-1",
        )


def test_stage366_publication_state_rejects_duplicate_file_across_jobs(tmp_path: Path) -> None:
    sample = tmp_path / "same.bin"
    sample.write_bytes(b"payload")
    state = rq._record_result_publication(
        rq.QueuePublicationState.empty(),
        {"job_id": "job-1", "file": str(sample)},
        {"job-1", "job-2"},
        {"job-1", "job-2"},
        worker_id="worker-1",
    )

    with pytest.raises(RuntimeError, match="duplicate scheduler file result publication"):
        rq._record_result_publication(
            state,
            {"job_id": "job-2", "file": str(sample)},
            {"job-1", "job-2"},
            {"job-1", "job-2"},
            worker_id="worker-2",
        )


def test_stage366_archive_child_publications_remain_distinct(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(b"PK\x03\x04")
    state = rq._record_result_publication(
        rq.QueuePublicationState.empty(),
        {"job_id": "job-a", "file": str(archive), "archive_child_identity": "a.bin"},
        {"job-a", "job-b"},
        {"job-a", "job-b"},
    )
    state = rq._record_result_publication(
        state,
        {"job_id": "job-b", "file": str(archive), "archive_child_identity": "b.bin"},
        {"job-a", "job-b"},
        {"job-a", "job-b"},
    )

    assert state.as_dict()["job_identities"] == ["job-a", "job-b"]
    assert len(state.file_identities) == 2


def test_stage366_recovery_batch_rejects_duplicate_job_decisions(tmp_path: Path) -> None:
    sample = tmp_path / "crash.bin"
    sample.write_bytes(b"x")
    decision = rq.classify_recovery_decision(
        {"job_id": "job-1", "file": str(sample), "attempt": 1, "max_attempts": 2},
        {"worker_id": "worker-1"},
        "worker crash mid-file",
    )

    with pytest.raises(RuntimeError, match="duplicate scheduler recovery decision"):
        rq._validate_recovery_decision_batch([decision, decision])


def test_stage366_apply_recovery_decisions_rejects_noncanonical_records(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    with pytest.raises(RuntimeError, match="not immutable/canonical"):
        rq._apply_recovery_decisions(tmp_path, [{"job_id": "job-1"}])


def test_stage366_terminal_accounting_rejects_claimed_job_without_final_state() -> None:
    with pytest.raises(RuntimeError, match="claimed scheduler jobs lack final state"):
        rq._validate_terminal_job_accounting({"job-1", "job-2"}, {"job-1"}, [])


def test_stage366_terminal_accounting_accepts_explicit_worker_failure_record() -> None:
    record = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-2",
        file_path="/tmp/sample.bin",
        failure_reason="timeout",
        requeued=False,
        failed=True,
        attempt_count=2,
        final_scheduler_action="fail",
    )

    assert rq._validate_terminal_job_accounting({"job-1", "job-2"}, {"job-1"}, [record]) is True


def test_stage366_worker_failure_accounting_rejects_negative_attempt() -> None:
    record = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-1",
        file_path="/tmp/sample.bin",
        failure_reason="timeout",
        requeued=False,
        failed=True,
        attempt_count=-1,
        final_scheduler_action="fail",
    )
    with pytest.raises(RuntimeError, match="negative attempt"):
        record.assert_valid()


def test_stage366_finalize_rejects_orphan_claim_meta(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    (tmp_path / "active" / "job-1.qmeta.json").write_text(json.dumps({"job_id": "job-1"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="orphan queue locks"):
        rq._finalize_queue_run(tmp_path)
