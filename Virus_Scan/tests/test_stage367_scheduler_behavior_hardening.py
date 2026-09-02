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


def _job_payload(job_id: str, file_path: Path) -> dict[str, object]:
    return {"job_type": "raw_stage", "job_id": job_id, "file": str(file_path), "file_id": job_id, "collector": "raw", "seq": 0}


def test_stage367_finalize_rejects_pending_queue_files(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    (tmp_path / "pending" / "job-1.json").write_text(json.dumps(_job_payload("job-1", sample)), encoding="utf-8")

    with pytest.raises(RuntimeError, match="unfinished scheduler work"):
        rq._finalize_queue_run(tmp_path)


def test_stage367_finalize_rejects_active_unfinished_job(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    (tmp_path / "active" / "job-1.json").write_text(json.dumps(_job_payload("job-1", sample)), encoding="utf-8")

    with pytest.raises(RuntimeError, match="unfinished scheduler work"):
        rq._finalize_queue_run(tmp_path)


def test_stage367_queue_phase_ledger_is_immutable_and_ordered() -> None:
    planning = rq.QueueBehaviorSnapshot.from_counts("planning", {"pending": 1, "total": 1})
    dispatch = rq.QueueBehaviorSnapshot.from_counts("dispatch", {"pending": 1, "total": 1})
    ledger = rq.QueuePhaseLedger(())
    next_ledger = ledger.with_snapshot(planning).with_snapshot(dispatch)
    assert ledger.snapshots == ()
    assert [snapshot.phase for snapshot in next_ledger.snapshots] == ["planning", "dispatch"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        next_ledger.snapshots = ()  # type: ignore[misc]


def test_stage367_queue_phase_ledger_rejects_phase_regression() -> None:
    dispatch = rq.QueueBehaviorSnapshot.from_counts("dispatch", {"pending": 1, "total": 1})
    planning = rq.QueueBehaviorSnapshot.from_counts("planning", {"pending": 1, "total": 1})
    with pytest.raises(RuntimeError, match="phase regression"):
        rq.QueuePhaseLedger(()).with_snapshot(dispatch).with_snapshot(planning)


def test_stage367_queue_phase_ledger_requires_declared_major_phases() -> None:
    ledger = rq.QueuePhaseLedger((rq.QueueBehaviorSnapshot.from_counts("planning", {"total": 0}),))
    with pytest.raises(RuntimeError, match="missing phases"):
        ledger.assert_contains(("planning", "finalize"))


def test_stage367_enqueue_helper_requires_explicit_archive_expansion(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    a = tmp_path / "a.bin"; a.write_bytes(b"a")
    b = tmp_path / "b.bin"; b.write_bytes(b"b")
    (tmp_path / "pending" / "a.json").write_text(json.dumps(_job_payload("a", a)), encoding="utf-8")
    planning = rq._record_queue_snapshot(tmp_path, "planning", total=1)
    (tmp_path / "pending" / "b.json").write_text(json.dumps(_job_payload("b", b)), encoding="utf-8")
    with pytest.raises(RuntimeError, match="queue total changed"):
        rq._enqueue_queue_jobs(tmp_path, planning, total=2)
    expanded = rq._enqueue_queue_jobs(tmp_path, planning, total=2, allow_total_expansion=True)
    assert expanded.pending == 2
    assert expanded.total == 2


def test_stage367_claim_helper_detects_counter_overflow(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    a = tmp_path / "a.bin"; a.write_bytes(b"a")
    (tmp_path / "active" / "a.json").write_text(json.dumps(_job_payload("a", a)), encoding="utf-8")
    with pytest.raises(RuntimeError, match="counter overflow"):
        rq._claim_ready_jobs(tmp_path, total=0)


def test_stage367_worker_lifecycle_cleanup_uses_queue_directory_state(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    a = tmp_path / "a.bin"; a.write_bytes(b"a")
    (tmp_path / "pending" / "a.json").write_text(json.dumps(_job_payload("a", a)), encoding="utf-8")
    with pytest.raises(RuntimeError, match="unfinished scheduler work"):
        rq._validate_worker_lifecycle_cleanup(tmp_path, [])


def test_stage367_recovery_decision_quarantines_malformed_result(tmp_path: Path) -> None:
    sample = tmp_path / "malformed.bin"
    sample.write_bytes(b"x")
    job = {"job_id": "job-malformed", "file": str(sample), "attempt": 0, "max_attempts": 3}
    worker = {"worker_id": "worker-1", "source_event": "result_parse"}
    decision = rq.classify_recovery_decision(job, worker, "malformed result JSON")
    assert decision.final_action == "quarantine"
    accounting = rq._record_worker_failure_accounting(job, worker, "malformed result JSON")
    assert accounting.final_scheduler_action == "quarantine"
    assert accounting.failed is True
