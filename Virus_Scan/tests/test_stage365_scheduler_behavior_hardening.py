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


def test_stage365_finalize_requires_emitted_and_finalized_counts_to_match(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    with pytest.raises(RuntimeError, match="queue finalization mismatch"):
        rq._finalize_queue_run(tmp_path, emitted_result_count=1, finalized_count=0)


def test_stage365_archive_child_expansion_requires_explicit_total_expansion_record() -> None:
    planning = rq.QueueBehaviorSnapshot.from_counts("planning", {"pending": 1, "total": 1})
    expanded = rq.QueueBehaviorSnapshot.from_counts("enqueue", {"pending": 2, "total": 2})
    with pytest.raises(RuntimeError, match="queue total changed"):
        rq._validate_queue_integrity(planning, expanded)
    assert rq._validate_queue_integrity(planning, expanded, allow_total_expansion=True).total == 2


def test_stage365_recovery_decision_is_immutable_and_rejects_negative_attempt(tmp_path: Path) -> None:
    sample = tmp_path / "worker.bin"
    sample.write_bytes(b"x")
    decision = rq.classify_recovery_decision(
        {"job_id": "job-1", "file": str(sample), "attempt": 0, "max_attempts": 2},
        {"worker_id": "worker-1", "source_event": "worker_crash"},
        "worker crash mid-file",
    )
    assert decision.final_action == "requeue"
    assert decision.source_event == "worker_crash"
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.final_action = "fail"  # type: ignore[misc]
    bad = rq.QueueRecoveryDecision(
        job_id="job-1",
        worker_id="worker-1",
        file_path=str(sample),
        failure_reason="worker crash",
        final_action="fail",
        reason_text="fail:worker crash",
        attempt_count=-1,
        source_event="worker_crash",
    )
    with pytest.raises(RuntimeError, match="negative attempt"):
        bad.assert_valid()


def test_stage365_worker_failure_accounting_action_booleans_must_match() -> None:
    bad = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-1",
        file_path="/tmp/sample.bin",
        failure_reason="timeout",
        requeued=True,
        failed=False,
        attempt_count=1,
        final_scheduler_action="fail",
    )
    with pytest.raises(RuntimeError, match="fail action is inconsistent"):
        bad.assert_valid()


def test_stage365_malformed_scheduler_result_without_identity_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="scheduler result missing job identity"):
        rq.validate_result_publication(ResultPublicationValidationRequest(
            {"verdict": "Clean"},
            {"job-1"},
            {"job-1"},
            set(),
            worker_id="worker-1",
        ))


def test_stage365_worker_ownership_mismatch_is_rejected(tmp_path: Path) -> None:
    sample = tmp_path / "owned.bin"
    sample.write_bytes(b"payload")
    with pytest.raises(RuntimeError, match="worker ownership mismatch"):
        rq.validate_result_publication(ResultPublicationValidationRequest(
            {"job_id": "job-owned", "file": str(sample)},
            {"job-owned"},
            {"job-owned"},
            set(),
            worker_id="worker-2",
            worker_ownership={"job-owned": "worker-1"},
        ))


def test_stage365_orphan_claim_files_are_rejected_at_finalize(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    (tmp_path / "active" / "job-1.claim").write_text(json.dumps({"job_id": "job-1"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="orphan queue locks"):
        rq._finalize_queue_run(tmp_path)
