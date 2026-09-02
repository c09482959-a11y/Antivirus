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


def _final_state(tmp_path: Path, *, count: int = 1) -> QueueRunFinalizationState:
    _queue_dirs(tmp_path)
    ledger = rq.QueuePhaseLedger(())
    for phase in ("planning", "enqueue", "dispatch", "collect"):
        ledger = ledger.with_snapshot(_snapshot(phase, total=count))
    publication = rq.QueuePublicationState.empty()
    for idx in range(count):
        job_id = f"job-{idx}"
        publication = publication.with_publication({"job_id": job_id, "file": str(tmp_path / f"sample-{idx}.bin")})
    return rq._finalize_queue_run_state(
        tmp_path,
        ledger,
        publication,
        emitted_result_count=count,
        finalized_count=count,
        total=count,
    )


def _result(tmp_path: Path, idx: int = 0, *, verdict: str = "Clean") -> dict[str, object]:
    return {
        "job_id": f"job-{idx}",
        "file": str(tmp_path / f"sample-{idx}.bin"),
        "verdict": verdict,
        "tags": ["tag-a"],
        "chains": ["chain-a"],
        "engine": "other",
    }


def test_stage370_hardening_report_binds_finalization_and_replay(tmp_path: Path) -> None:
    state = _final_state(tmp_path)
    report = rq._build_scheduler_behavior_hardening_report(
        state,
        [_result(tmp_path)],
        scheduler_behavior_rating=8.7,
        overall_forensic_rating=8.5,
    )
    data = report.as_dict()
    assert data["replay_snapshot"]["emitted_result_count"] == 1
    assert data["finalization_state"]["emitted_result_count"] == 1


def test_stage370_hardening_report_is_immutable(tmp_path: Path) -> None:
    report = rq._build_scheduler_behavior_hardening_report(
        _final_state(tmp_path),
        [_result(tmp_path)],
        scheduler_behavior_rating=8.7,
        overall_forensic_rating=8.5,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.scheduler_behavior_rating = 1.0  # type: ignore[misc]


def test_stage370_hardening_report_rejects_replay_publication_count_mismatch(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="replay count"):
        rq._build_scheduler_behavior_hardening_report(
            _final_state(tmp_path, count=2),
            [_result(tmp_path, 0)],
            scheduler_behavior_rating=8.7,
            overall_forensic_rating=8.5,
        )


def test_stage370_hardening_report_rejects_invalid_scheduler_rating(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="scheduler behavior rating"):
        rq._build_scheduler_behavior_hardening_report(
            _final_state(tmp_path),
            [_result(tmp_path)],
            scheduler_behavior_rating=10.1,
            overall_forensic_rating=8.5,
        )


def test_stage370_hardening_report_rejects_invalid_overall_rating(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="overall forensic rating"):
        rq._build_scheduler_behavior_hardening_report(
            _final_state(tmp_path),
            [_result(tmp_path)],
            scheduler_behavior_rating=8.7,
            overall_forensic_rating=-0.1,
        )


def test_stage370_hardening_report_rejects_duplicate_replay_jobs(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="duplicate job ids"):
        rq._build_scheduler_behavior_hardening_report(
            _final_state(tmp_path, count=2),
            [_result(tmp_path, 0), {**_result(tmp_path, 1), "job_id": "job-0"}],
            scheduler_behavior_rating=8.7,
            overall_forensic_rating=8.5,
        )


def test_stage370_hardening_report_preserves_multiple_replay_records(tmp_path: Path) -> None:
    state = _final_state(tmp_path, count=2)
    report = rq._build_scheduler_behavior_hardening_report(
        state,
        [_result(tmp_path, 1, verdict="Low"), _result(tmp_path, 0, verdict="Clean")],
        scheduler_behavior_rating=8.7,
        overall_forensic_rating=8.5,
    )
    assert [record.job_id for record in report.replay_snapshot.records] == ["job-0", "job-1"]
