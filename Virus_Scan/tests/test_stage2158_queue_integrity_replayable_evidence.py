from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.integrity import (
    QUEUE_IDENTITY_COLLECTION_FAILED,
    QueueIntegrityVerificationRequest,
    _expected_file_count,
    _identity_collection_failed_records,
    verify_and_repair_queue_integrity,
)


class HostileGroups:
    touched = 0

    def __getattribute__(self, name: str):  # pragma: no cover - must not be invoked
        type(self).touched += 1
        raise AssertionError("hostile groups touched")


def test_stage2158_identity_failure_records_are_replayable_without_hooks() -> None:
    HostileGroups.touched = 0

    decision = _identity_collection_failed_records(HostileGroups())

    assert decision.accepted is False
    assert decision.records == ()
    assert decision.reason == "queue_identity_groups_rejected"
    assert ("decision", "queue_identity_failure_records") in decision.evidence
    assert HostileGroups.touched == 0


def test_stage2158_identity_failure_records_distinguish_absent_from_failure_record() -> None:
    absent = _identity_collection_failed_records({})
    failed = _identity_collection_failed_records(
        {
            QUEUE_IDENTITY_COLLECTION_FAILED: [
                {
                    "state": "queue_identity_collection_failed",
                    "queue_integrity_unavailable": True,
                }
            ]
        }
    )

    assert absent.accepted is True
    assert absent.records == ()
    assert absent.reason == "queue_identity_failure_records_absent"
    assert failed.accepted is True
    assert len(failed.records) == 1
    assert failed.reason == "queue_identity_failure_records_materialized"


def test_stage2158_missing_expected_files_is_typed_replayable_evidence(tmp_path: Path) -> None:
    summary = verify_and_repair_queue_integrity(QueueIntegrityVerificationRequest(
        tmp_path,
        all_files=None,
        phase="startup",
        repair=True,
        ensure_dirs=lambda _q: None,
        cleanup_diagnostic_tmp_files=lambda _q, max_age_sec=60.0: None,
        identity_collector=lambda _q: {},
        active_claim_is_protected=lambda *a, **k: False,
        quarantine_job=lambda *a, **k: True,
        queue_now=lambda: 1.0,
        report=lambda *a, **k: None,
    ))

    assert summary["expected_files"] is None
    assert ["reason", "queue_expected_file_count_missing"] in summary["expected_files_evidence"]
    assert ["decision", "queue_expected_file_count"] in summary["expected_files_evidence"]
    assert summary["integrity_complete"] is True


def test_stage2158_expected_file_count_materializes_without_iteration_hooks() -> None:
    missing = _expected_file_count(None)
    present = _expected_file_count(("a.json", "b.json"))

    assert missing.accepted is False
    assert missing.count is None
    assert present.accepted is True
    assert present.count == 2
