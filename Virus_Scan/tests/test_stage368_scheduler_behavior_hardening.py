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


def _base_ledger(total: int = 1) -> QueuePhaseLedger:
    ledger = rq.QueuePhaseLedger(())
    for phase in ("planning", "enqueue", "dispatch", "collect"):
        ledger = ledger.with_snapshot(_snapshot(phase, total=total))
    return ledger


def test_stage368_queue_run_finalization_state_is_immutable(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    result = {"job_id": "job-1", "file": str(tmp_path / "sample.bin")}
    publication = rq.QueuePublicationState.empty().with_publication(result)
    state = rq._finalize_queue_run_state(
        tmp_path,
        _base_ledger(),
        publication,
        emitted_result_count=1,
        finalized_count=1,
        total=1,
    )
    state.assert_valid()
    assert state.phase_ledger.snapshots[-1].phase == "finalize"
    with pytest.raises(dataclasses.FrozenInstanceError):
        state.finalized_count = 0  # type: ignore[misc]


def test_stage368_finalization_state_rejects_publication_count_mismatch(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    publication = rq.QueuePublicationState.empty()
    with pytest.raises(RuntimeError, match="publication count"):
        rq._finalize_queue_run_state(
            tmp_path,
            _base_ledger(),
            publication,
            emitted_result_count=1,
            finalized_count=1,
            total=1,
        )


def test_stage368_finalization_state_rejects_result_count_mismatch() -> None:
    result = {"job_id": "job-1", "file": "/tmp/stage368.bin"}
    publication = rq.QueuePublicationState.empty().with_publication(result)
    state = rq.QueueRunFinalizationState(
        phase_ledger=_base_ledger().with_snapshot(_snapshot("finalize")),
        publication_state=publication,
        worker_failures=(),
        emitted_result_count=1,
        finalized_count=0,
    )
    with pytest.raises(RuntimeError, match="result mismatch"):
        state.assert_valid()


def test_stage368_finalization_state_requires_final_snapshot() -> None:
    result = {"job_id": "job-1", "file": "/tmp/stage368.bin"}
    publication = rq.QueuePublicationState.empty().with_publication(result)
    state = rq.QueueRunFinalizationState(
        phase_ledger=_base_ledger(),
        publication_state=publication,
        worker_failures=(),
        emitted_result_count=1,
        finalized_count=1,
    )
    with pytest.raises(RuntimeError, match="missing phases"):
        state.assert_valid()


def test_stage368_finalization_state_rejects_noncanonical_worker_accounting() -> None:
    result = {"job_id": "job-1", "file": "/tmp/stage368.bin"}
    publication = rq.QueuePublicationState.empty().with_publication(result)
    state = rq.QueueRunFinalizationState(
        phase_ledger=_base_ledger().with_snapshot(_snapshot("finalize")),
        publication_state=publication,
        worker_failures=(object(),),  # type: ignore[arg-type]
        emitted_result_count=1,
        finalized_count=1,
    )
    with pytest.raises(RuntimeError, match="worker accounting"):
        state.assert_valid()


def test_stage368_finalization_rejects_unfinished_queue_before_state(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    (tmp_path / "pending" / "job-1.json").write_text('{"job_id":"job-1","file":"sample.bin"}', encoding="utf-8")
    result = {"job_id": "job-1", "file": str(tmp_path / "sample.bin")}
    publication = rq.QueuePublicationState.empty().with_publication(result)
    with pytest.raises(RuntimeError, match="unfinished scheduler work"):
        rq._finalize_queue_run_state(
            tmp_path,
            _base_ledger(),
            publication,
            emitted_result_count=1,
            finalized_count=1,
            total=1,
        )


def test_stage368_finalization_state_serializes_canonical_order(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    publication = rq.QueuePublicationState.empty()
    for job_id in ("job-b", "job-a"):
        publication = publication.with_publication({"job_id": job_id, "file": str(tmp_path / f"{job_id}.bin")})
    state = rq._finalize_queue_run_state(
        tmp_path,
        _base_ledger(total=2),
        publication,
        emitted_result_count=2,
        finalized_count=2,
        total=2,
    )
    data = state.as_dict()
    assert data["publication_state"]["job_identities"] == ["job-a", "job-b"]
    assert [s["phase"] for s in data["phase_ledger"]["snapshots"]][-1] == "finalize"
