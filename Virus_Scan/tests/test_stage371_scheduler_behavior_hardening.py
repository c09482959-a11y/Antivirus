from __future__ import annotations

import dataclasses
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


def _snapshot(phase: str, total: int = 1) -> QueueBehaviorSnapshot:
    return rq.QueueBehaviorSnapshot.from_counts(phase, {"total": total})


def _complete_ledger(total: int = 1) -> QueuePhaseLedger:
    ledger = rq.QueuePhaseLedger(())
    for phase in ("planning", "enqueue", "dispatch", "claim", "collect", "recover", "publish"):
        ledger = ledger.with_snapshot(_snapshot(phase, total=total))
    return ledger


def _publication(tmp_path: Path, count: int = 1) -> QueuePublicationState:
    state = rq.QueuePublicationState.empty()
    for idx in range(count):
        state = state.with_publication({"job_id": f"job-{idx}", "file": str(tmp_path / f"sample-{idx}.bin")})
    return state


def _final_state(tmp_path: Path, *, count: int = 1, worker_failures=()) -> QueueRunFinalizationState:
    _queue_dirs(tmp_path)
    return rq._finalize_queue_run_state(
        tmp_path,
        _complete_ledger(total=count),
        _publication(tmp_path, count),
        worker_failures,
        emitted_result_count=count,
        finalized_count=count,
        total=count,
    )


def _result(tmp_path: Path, idx: int = 0, *, recovery_count: int = 0, failed_count: int = 0) -> dict[str, object]:
    return {
        "job_id": f"job-{idx}",
        "file": str(tmp_path / f"sample-{idx}.bin"),
        "verdict": "Clean" if failed_count == 0 else "High",
        "tags": ["tag-a"],
        "chains": ["chain-a"],
        "engine": "other",
        "recovery_count": recovery_count,
        "failed_count": failed_count,
    }


def test_stage371_scheduler_behavior_audit_requires_complete_phase_coverage(tmp_path: Path) -> None:
    audit = rq._build_scheduler_behavior_audit(
        _final_state(tmp_path),
        [_result(tmp_path)],
        scheduler_behavior_rating=8.8,
        overall_forensic_rating=8.6,
    )
    data = audit.as_dict()
    assert data["required_phases"] == ["planning", "enqueue", "dispatch", "claim", "collect", "recover", "publish", "finalize"]


def test_stage371_scheduler_behavior_audit_is_immutable(tmp_path: Path) -> None:
    audit = rq._build_scheduler_behavior_audit(
        _final_state(tmp_path),
        [_result(tmp_path)],
        scheduler_behavior_rating=8.8,
        overall_forensic_rating=8.6,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        audit.required_phases = ()  # type: ignore[misc]


def test_stage371_scheduler_behavior_audit_rejects_missing_phase(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    ledger = rq.QueuePhaseLedger(())
    for phase in ("planning", "enqueue", "dispatch", "collect"):
        ledger = ledger.with_snapshot(_snapshot(phase))
    state = rq._finalize_queue_run_state(
        tmp_path,
        ledger,
        _publication(tmp_path),
        emitted_result_count=1,
        finalized_count=1,
        total=1,
    )
    with pytest.raises(RuntimeError, match="missing queue phases"):
        rq._build_scheduler_behavior_audit(
            state,
            [_result(tmp_path)],
            scheduler_behavior_rating=8.8,
            overall_forensic_rating=8.6,
        )


def test_stage371_scheduler_behavior_audit_rejects_requeue_without_recovery_count(tmp_path: Path) -> None:
    failure = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-0",
        file_path=str(tmp_path / "sample-0.bin"),
        failure_reason="timeout",
        requeued=True,
        failed=False,
        attempt_count=1,
        final_scheduler_action="requeue",
    )
    state = _final_state(tmp_path, worker_failures=(failure,))
    with pytest.raises(RuntimeError, match="requeue accounting"):
        rq._build_scheduler_behavior_audit(
            state,
            [_result(tmp_path, recovery_count=0)],
            scheduler_behavior_rating=8.8,
            overall_forensic_rating=8.6,
        )


def test_stage371_scheduler_behavior_audit_accepts_requeue_with_recovery_count(tmp_path: Path) -> None:
    failure = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-0",
        file_path=str(tmp_path / "sample-0.bin"),
        failure_reason="timeout",
        requeued=True,
        failed=False,
        attempt_count=1,
        final_scheduler_action="requeue",
    )
    audit = rq._build_scheduler_behavior_audit(
        _final_state(tmp_path, worker_failures=(failure,)),
        [_result(tmp_path, recovery_count=1)],
        scheduler_behavior_rating=8.8,
        overall_forensic_rating=8.6,
    )
    assert audit.hardening_report.replay_snapshot.recovery_count == 1


def test_stage371_scheduler_behavior_audit_rejects_failed_accounting_without_failed_replay_count(tmp_path: Path) -> None:
    failure = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-0",
        file_path=str(tmp_path / "sample-0.bin"),
        failure_reason="worker_killed",
        requeued=False,
        failed=True,
        attempt_count=2,
        final_scheduler_action="fail",
    )
    state = _final_state(tmp_path, worker_failures=(failure,))
    with pytest.raises(RuntimeError, match="failed replay count"):
        rq._build_scheduler_behavior_audit(
            state,
            [_result(tmp_path, failed_count=0)],
            scheduler_behavior_rating=8.8,
            overall_forensic_rating=8.6,
        )


def test_stage371_scheduler_behavior_audit_accepts_failed_accounting_with_failed_replay_count(tmp_path: Path) -> None:
    failure = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-0",
        file_path=str(tmp_path / "sample-0.bin"),
        failure_reason="worker_killed",
        requeued=False,
        failed=True,
        attempt_count=2,
        final_scheduler_action="fail",
    )
    audit = rq._build_scheduler_behavior_audit(
        _final_state(tmp_path, worker_failures=(failure,)),
        [_result(tmp_path, failed_count=1)],
        scheduler_behavior_rating=8.8,
        overall_forensic_rating=8.6,
    )
    assert audit.hardening_report.replay_snapshot.failed_count == 1
