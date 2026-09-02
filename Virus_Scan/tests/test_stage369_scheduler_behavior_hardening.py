from __future__ import annotations

import dataclasses

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


def _result(job_id: str, file_path: str, *, verdict: str = "Clean", tags=None, chains=None, engine: str = "other", **extra):
    payload = {
        "job_id": job_id,
        "file": file_path,
        "verdict": verdict,
        "tags": list(tags or ()),
        "chains": list(chains or ()),
        "engine": engine,
    }
    payload.update(extra)
    return payload


def test_stage369_replay_snapshot_ignores_volatile_runtime_fields() -> None:
    first = [
        _result(
            "job-a",
            "/tmp/run-one/sample.bin",
            tags=["tag1", "tag2"],
            chains=["chain1"],
            timestamp="2026-01-01T00:00:00Z",
            duration=1.2,
            pid=123,
        )
    ]
    second = [
        _result(
            "job-a",
            "/tmp/run-one/sample.bin",
            tags=["tag1", "tag2"],
            chains=["chain1"],
            timestamp="2026-01-02T00:00:00Z",
            duration=9.9,
            pid=999,
        )
    ]
    snapshot = rq.assert_scheduler_replay_equivalent(first, second)
    assert snapshot.job_count == 1
    assert snapshot.emitted_result_count == 1


def test_stage369_replay_snapshot_sorts_worker_order_deterministically() -> None:
    serial = [
        _result("job-b", "/tmp/corpus/b.bin", verdict="Low", tags=["b"], chains=["cb"]),
        _result("job-a", "/tmp/corpus/a.bin", verdict="High", tags=["a"], chains=["ca"]),
    ]
    process = list(reversed(serial))
    snapshot = rq.assert_scheduler_replay_equivalent(serial, process)
    assert [record.job_id for record in snapshot.records] == ["job-a", "job-b"]


def test_stage369_replay_snapshot_rejects_verdict_drift() -> None:
    with pytest.raises(RuntimeError, match="replay comparison mismatch"):
        rq.assert_scheduler_replay_equivalent(
            [_result("job-a", "/tmp/corpus/a.bin", verdict="Clean")],
            [_result("job-a", "/tmp/corpus/a.bin", verdict="Malicious")],
        )


def test_stage369_replay_snapshot_canonicalizes_tag_order_without_false_mismatch() -> None:
    snapshot = rq.assert_scheduler_replay_equivalent(
        [_result("job-a", "/tmp/corpus/a.bin", tags=["first", "second"])],
        [_result("job-a", "/tmp/corpus/a.bin", tags=["second", "first"])],
    )
    assert snapshot.records[0].tags == ("first", "second")


def test_stage369_replay_snapshot_rejects_tag_content_drift() -> None:
    with pytest.raises(RuntimeError, match="replay comparison mismatch"):
        rq.assert_scheduler_replay_equivalent(
            [_result("job-a", "/tmp/corpus/a.bin", tags=["first", "second"])],
            [_result("job-a", "/tmp/corpus/a.bin", tags=["first", "third"])],
        )


def test_stage369_replay_snapshot_rejects_engine_routing_drift() -> None:
    with pytest.raises(RuntimeError, match="replay comparison mismatch"):
        rq.assert_scheduler_replay_equivalent(
            [_result("job-a", "/tmp/corpus/game.bin", engine="renpy")],
            [_result("job-a", "/tmp/corpus/game.bin", engine="unity")],
        )


def test_stage369_replay_snapshot_rejects_duplicate_job_ids() -> None:
    with pytest.raises(RuntimeError, match="duplicate job ids"):
        rq.normalize_scheduler_replay_results(
            [
                _result("job-a", "/tmp/corpus/a.bin"),
                _result("job-a", "/tmp/corpus/b.bin"),
            ]
        )


def test_stage369_replay_snapshot_rejects_duplicate_file_identities() -> None:
    with pytest.raises(RuntimeError, match="duplicate file identities"):
        rq.normalize_scheduler_replay_results(
            [
                _result("job-a", "/tmp/corpus/a.bin"),
                _result("job-b", "/tmp/corpus/a.bin"),
            ]
        )


def test_stage369_replay_snapshot_preserves_failure_recovery_counts() -> None:
    snapshot = rq.normalize_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", duplicate_count=1, recovery_count=2, failed_count=1)]
    )
    assert snapshot.duplicate_count == 1
    assert snapshot.recovery_count == 2
    assert snapshot.failed_count == 1


def test_stage369_replay_snapshot_is_immutable() -> None:
    snapshot = rq.normalize_scheduler_replay_results([_result("job-a", "/tmp/corpus/a.bin")])
    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.records = ()  # type: ignore[misc]
