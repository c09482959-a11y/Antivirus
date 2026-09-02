from __future__ import annotations

import json
from pathlib import Path

import pytest

from types import SimpleNamespace

from Virus_Scan.scheduler.queue.snapshots import QueueBehaviorSnapshot, QueuePhaseLedger
from Virus_Scan.scheduler.queue.publication_state import QueuePublicationState, QueueRunFinalizationState, _result_publication_file_identity
from Virus_Scan.scheduler.queue.recovery_contracts import QueueRecoveryDecision, QueueWorkerFailureAccounting
from Virus_Scan.scheduler.queue.recovery_decisions import (
    classify_queue_failure,
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
    classify_queue_failure=classify_queue_failure,
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


def _write_job(path: Path, file_path: Path, *, job_id: str | None = None, worker_id: str | None = None) -> None:
    payload = {"file": str(file_path)}
    if job_id:
        payload["job_id"] = job_id
    if worker_id:
        payload["worker_id"] = worker_id
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_stage363_queue_behavior_snapshot_rejects_counter_regression() -> None:
    before = rq.QueueBehaviorSnapshot.from_counts("collect", {"completed": 5, "failed": 2, "total": 10})
    after = rq.QueueBehaviorSnapshot.from_counts("publish", {"completed": 4, "failed": 2, "total": 10})

    with pytest.raises(RuntimeError, match="files_done decreased"):
        rq._validate_queue_integrity(before, after)


def test_stage363_queue_behavior_snapshot_rejects_finalization_mismatch() -> None:
    snapshot = rq.QueueBehaviorSnapshot.from_counts(
        "finalize",
        {"completed": 2, "failed": 1, "total": 3, "finalized_count": 3, "emitted_result_count": 2},
    )

    with pytest.raises(RuntimeError, match="finalization mismatch"):
        rq._validate_queue_integrity(None, snapshot)


def test_stage363_duplicate_result_publication_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"x")
    identity = rq._queue_file_identity_for_path(str(file_path))
    result = {"file": str(file_path), "verdict": "Clean"}

    with pytest.raises(RuntimeError, match="duplicate scheduler result publication"):
        rq.validate_result_publication(ResultPublicationValidationRequest(result, {identity}, {identity}, {identity}, worker_id="w1"))


def test_stage363_unknown_and_unclaimed_results_are_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "unknown.bin"
    file_path.write_bytes(b"x")
    identity = rq._queue_file_identity_for_path(str(file_path))
    result = {"file": str(file_path), "verdict": "Clean"}

    with pytest.raises(RuntimeError, match="unknown job"):
        rq.validate_result_publication(ResultPublicationValidationRequest(result, {"other"}, {identity}, set(), worker_id="w1"))

    with pytest.raises(RuntimeError, match="unclaimed job"):
        rq.validate_result_publication(ResultPublicationValidationRequest(result, {identity}, {"other"}, set(), worker_id="w1"))


def test_stage363_worker_ownership_mismatch_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "owned.bin"
    file_path.write_bytes(b"x")
    identity = rq._queue_file_identity_for_path(str(file_path))

    with pytest.raises(RuntimeError, match="worker ownership mismatch"):
        rq.validate_result_publication(ResultPublicationValidationRequest(
            {"file": str(file_path)},
            {identity},
            {identity},
            set(),
            worker_id="worker-b",
            worker_ownership={identity: "worker-a"},
        ))


def test_stage363_recovery_decision_is_explicit_and_immutable(tmp_path: Path) -> None:
    file_path = tmp_path / "crash.bin"
    file_path.write_bytes(b"x")

    decision = rq.classify_recovery_decision(
        {"job_id": "job-1", "file": str(file_path), "attempt": 0, "max_attempts": 2},
        {"worker_id": "worker-7", "source_event": "worker_exit"},
        "worker crashed mid-file",
    )

    assert decision.job_id == "job-1"
    assert decision.worker_id == "worker-7"
    assert decision.file_path == str(file_path)
    assert decision.final_action == "requeue"
    assert decision.attempt_count == 0
    assert decision.source_event == "worker_exit"
    with pytest.raises(Exception):
        decision.final_action = "fail"  # type: ignore[misc]


def test_stage363_recovery_decision_fails_after_attempt_budget(tmp_path: Path) -> None:
    file_path = tmp_path / "timeout.bin"
    file_path.write_bytes(b"x")

    decision = rq.classify_recovery_decision(
        {"job_id": "job-2", "file": str(file_path), "attempt": 2, "max_attempts": 2},
        {"worker_id": "worker-8"},
        "timeout",
    )

    assert decision.final_action == "fail"
    assert decision.reason_text.startswith("fail:timeout")


def test_stage363_queue_snapshot_records_orphan_locks_and_finalization_fails(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    (tmp_path / "active" / "job-1.claim").write_text("locked", encoding="utf-8")
    snapshot = rq._record_queue_snapshot(tmp_path, "finalize", total=0)

    assert snapshot.orphan_lock_count == 1
    with pytest.raises(RuntimeError, match="orphan queue locks"):
        rq._validate_queue_integrity(None, snapshot)


def test_stage363_same_file_phase_helpers_validate_deterministic_progress(tmp_path: Path) -> None:
    _queue_dirs(tmp_path)
    corpus_file = tmp_path / "sample.bin"
    corpus_file.write_bytes(b"x")
    _write_job(tmp_path / "pending" / "job.json", corpus_file)

    planning = rq._record_queue_snapshot(tmp_path, "planning", total=1)
    dispatch = rq._dispatch_ready_jobs(tmp_path, planning, total=1)

    assert dispatch.pending == 1
    assert dispatch.total == 1


class _Stage1926HostileRecoveryValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __format__(self, spec):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")

    def __int__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ executed")

    @property
    def text(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned text property executed")


class _Stage1926HostileRecoveryError(Exception):
    touched = 0

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("caller-owned exception __str__ executed")


def test_stage1926_recovery_decision_rejects_hostile_fields_without_hooks(tmp_path: Path) -> None:
    _Stage1926HostileRecoveryValue.touched = 0
    file_path = tmp_path / "hostile-worker.bin"
    file_path.write_bytes(b"x")

    decision = rq.classify_recovery_decision(
        {
            "job_id": _Stage1926HostileRecoveryValue(),
            "file": str(file_path),
            "attempt": _Stage1926HostileRecoveryValue(),
            "max_attempts": _Stage1926HostileRecoveryValue(),
        },
        {
            "worker_id": _Stage1926HostileRecoveryValue(),
            "source_event": _Stage1926HostileRecoveryValue(),
        },
        _Stage1926HostileRecoveryValue(),
    )

    assert _Stage1926HostileRecoveryValue.touched == 0
    assert decision.job_id == rq._queue_file_identity_for_path(str(file_path))
    assert decision.worker_id == "unknown"
    assert decision.failure_reason == "worker_failure"
    assert decision.source_event == "scheduler_recovery"
    assert decision.attempt_count == 0


def test_stage1926_recovery_contract_validation_rejects_hostile_actions_without_hooks() -> None:
    _Stage1926HostileRecoveryValue.touched = 0
    bad_decision = rq.QueueRecoveryDecision(
        job_id="job-1",
        worker_id="worker-1",
        file_path="/tmp/sample.bin",
        failure_reason="timeout",
        final_action=_Stage1926HostileRecoveryValue(),  # type: ignore[arg-type]
        reason_text="fail:timeout",
        attempt_count=1,
        source_event="stage1926",
    )
    with pytest.raises(RuntimeError, match="HostileRecoveryValue"):
        bad_decision.assert_valid()

    bad_accounting = rq.QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-1",
        file_path="/tmp/sample.bin",
        failure_reason="timeout",
        requeued=False,
        failed=True,
        attempt_count=1,
        final_scheduler_action=_Stage1926HostileRecoveryValue(),  # type: ignore[arg-type]
    )
    with pytest.raises(RuntimeError, match="HostileRecoveryValue"):
        bad_accounting.assert_valid()
    assert _Stage1926HostileRecoveryValue.touched == 0


def test_stage1926_classify_queue_failure_uses_exception_args_without_str_hooks() -> None:
    _Stage1926HostileRecoveryError.touched = 0
    decision = rq.classify_queue_failure(_Stage1926HostileRecoveryError("worker timeout"), stage="recover")

    assert _Stage1926HostileRecoveryError.touched == 0
    assert decision.action == "retry"
    assert decision.reason == "recover:scheduler.queue"
