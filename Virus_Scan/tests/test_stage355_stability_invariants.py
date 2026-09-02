from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.contracts.result_record import ReplayComparableResultSnapshot, validate_replay_equivalent
from Virus_Scan.routing.context_identity import EngineContextIdentity
from Virus_Scan.scheduler.queue.integrity_contracts import (
    QueueIdentityRecord,
    QueueIntegritySummary,
    validate_queue_integrity_summary,
)
from Virus_Scan.scheduler.queue.integrity import (
    QueueIntegrityVerificationRequest,
    verify_and_repair_queue_integrity,
)


def _minimal_result(**changes):
    record = {
        "file": "sample.bin",
        "path": "sample.bin",
        "input_file_path": "sample.bin",
        "verdict": "malicious",
        "score": 91,
        "tags": ["encoded_payload", "powershell"],
        "chains": ["download_execute"],
        "decoded_evidence_snippets": ["powershell -enc AAAA"],
        "container_engine": "renpy",
        "artifact_engine": "unity",
        "effective_analysis_engine": "embedded_pe_payload",
    }
    record.update(changes)
    return record


def test_stage355_replay_snapshot_excludes_volatile_runtime_fields() -> None:
    first = _minimal_result(timestamp="2026-05-20T01:00:00Z", duration_seconds=1.25, worker_pid=11)
    second = _minimal_result(timestamp="2026-05-20T01:05:00Z", duration_seconds=9.50, worker_pid=99)

    assert ReplayComparableResultSnapshot.from_record(first) == ReplayComparableResultSnapshot.from_record(second)
    assert validate_replay_equivalent(first, second) is True


def test_stage355_replay_snapshot_detects_forensic_result_drift() -> None:
    first = _minimal_result(tags=["encoded_payload", "powershell"])
    second = _minimal_result(tags=["encoded_payload", "registry_persistence"])

    with pytest.raises(ValueError, match="deterministic replay mismatch"):
        validate_replay_equivalent(first, second)


def test_stage355_queue_identity_record_is_immutable_and_shape_checked(tmp_path: Path) -> None:
    record = QueueIdentityRecord.from_observation(
        state="pending",
        path=tmp_path / "job.json",
        name="job.json",
        job={"file": "sample.bin"},
    )

    with pytest.raises(Exception):
        record.state = "done"  # type: ignore[misc]
    with pytest.raises(ValueError, match="missing path"):
        QueueIdentityRecord.from_observation(state="pending", path="", name="job.json", job={})
    with pytest.raises(ValueError, match="job must be a mapping"):
        QueueIdentityRecord.from_observation(state="pending", path=tmp_path / "bad.json", name="bad.json", job=[])


def test_stage355_queue_integrity_summary_hard_fails_unrepaired_duplicates(tmp_path: Path) -> None:
    groups = {
        "file:x": [
            {"state": "done", "path": tmp_path / "done.json", "name": "done.json", "job": {"file": "x"}},
            {"state": "pending", "path": tmp_path / "pending.json", "name": "pending.json", "job": {"file": "x"}},
        ]
    }

    with pytest.raises(RuntimeError, match="queue integrity violations remain"):
        verify_and_repair_queue_integrity(QueueIntegrityVerificationRequest(
            tmp_path,
            all_files=None,
            phase="startup",
            repair=False,
            ensure_dirs=lambda _q: None,
            cleanup_diagnostic_tmp_files=lambda _q, max_age_sec=60.0: None,
            identity_collector=lambda _q: groups,
            active_claim_is_protected=lambda *a, **k: False,
            quarantine_job=lambda *a, **k: True,
            queue_now=lambda: 123.0,
            report=lambda *a, **k: None,
        ))


def test_stage355_queue_integrity_summary_requires_complete_clean_state() -> None:
    summary = QueueIntegritySummary(duplicates=1, invalid=0, quarantined=0, integrity_complete=True).as_dict()

    with pytest.raises(RuntimeError, match="duplicates=1 invalid=0"):
        validate_queue_integrity_summary(summary)


def test_stage355_engine_context_identity_hard_fails_invalid_routes() -> None:
    context = EngineContextIdentity(
        container_engine="unity",
        container_engine_confidence=1.0,
        artifact_engine="renpy",
        artifact_engine_confidence=1.0,
        declared_extension=".rpyc",
        sniffed_type="renpy_bytecode",
        sniffed_embedded_types=(),
        extension_mismatch=False,
        cross_engine_artifact=True,
        engine_mismatch=False,
        effective_analysis_engine="renpy_bytecode",
        baseline_key="unity::renpy::.rpyc::renpy_bytecode",
        extension_baseline="renpy/.rpyc",
        contextual_baseline="unity::renpy::.rpyc",
        container_extension_baseline="unity/.rpyc",
        secondary_baseline_keys=("renpy/.rpyc",),
        baseline_lookup_order=("unity::renpy::.rpyc::renpy_bytecode", "renpy/.rpyc"),
        learning_baseline_key=None,
        blocked_baseline_keys=("renpy/.rpyc",),
        learning_allowed=False,
        learning_reason="engine_mismatch",
        fingerprint_evidence=("extension:.rpyc",),
    )

    with pytest.raises(ValueError, match="cross-engine artifact"):
        context.validate()
