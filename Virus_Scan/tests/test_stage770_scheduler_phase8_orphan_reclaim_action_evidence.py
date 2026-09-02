from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.orphan_recovery_actions import requeue_reclaimed_active_job
from Virus_Scan.scheduler.queue.orphan_recovery_finish import (
    UnretryableReclaimedJobFinishRequest,
    finish_unretryable_reclaimed_job,
)
from Virus_Scan.scheduler.queue.reclaim_publication import _publish_reclaimed_pending_job


def _assert_reclaim_evidence(record, stage):
    assert record["stage"] == stage
    assert record["timeout_failure"] is True
    assert record["retry_failure"] is True
    assert record["queue_recovery_failure"] is True
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage770_reclaim_move_rejection_records_timeout_retry_evidence(tmp_path: Path):
    active_dir = tmp_path / "active"
    pending_dir = tmp_path / "pending"
    active_dir.mkdir()
    pending_dir.mkdir()
    src = active_dir / "job.json"
    src.write_text("{}", encoding="utf-8")
    src.unlink()
    evidence = []


    result = requeue_reclaimed_active_job(
        queue_dir=tmp_path,
        active_dir=active_dir,
        pending_dir=pending_dir,
        src=src,
        name="job.json",
        job={"file": "sample.bin"},
        queue_info={},
        now=100.0,
        attempt=0,
        info={"time": "2026-01-01T00:00:00Z"},
        evidence_records=evidence,
        safe_remove_claim_meta=lambda _path: True,
        cleanup_orphan_claim_meta=lambda *_args, **_kwargs: 0,
    )

    assert result is None
    assert evidence
    _assert_reclaim_evidence(evidence[0], "process_queue_reclaim_active_move_rejected")


def test_stage770_reclaimed_pending_annotation_failure_records_evidence(tmp_path: Path):
    pending_path = tmp_path / "pending.json"
    pending_path.write_text("{}", encoding="utf-8")
    (tmp_path / "quarantine").write_text("quarantine unavailable", encoding="utf-8")
    evidence = []


    result = _publish_reclaimed_pending_job(
        tmp_path,
        pending_path,
        {"file": "sample.bin", "reclaimed_from_active": True, "queue_failure": True},
        source_path=tmp_path / "active" / "job.json",
        evidence_records=evidence,
        safe_unlink=lambda *_args, **_kwargs: True,
    )

    assert result is False
    stages = [record["stage"] for record in evidence]
    assert "queue_reclaim_annotation_failed" in stages
    assert "queue_reclaim_annotation_quarantine_failed" in stages
    for record in evidence:
        _assert_reclaim_evidence(record, record["stage"])


def test_stage770_finish_unretryable_reclaimed_job_failure_records_evidence(tmp_path: Path):
    evidence = []


    def failing_finish(*_args, **_kwargs):
        raise RuntimeError("failed table unavailable")

    result = finish_unretryable_reclaimed_job(UnretryableReclaimedJobFinishRequest(
        tmp_path,
        tmp_path / "active" / "job.json",
        info={"stage": "timeout"},
        job={"file": "sample.bin"},
        evidence_records=evidence,
        finish_process_queue_job=failing_finish,
    ))

    assert result is False
    assert evidence
    _assert_reclaim_evidence(evidence[0], "process_queue_finish_after_reclaim_failed")
