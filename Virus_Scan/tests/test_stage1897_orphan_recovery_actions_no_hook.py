from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.orphan_recovery_action_evidence import (
    OrphanRecoveryActionEvidenceRequest,
    orphan_recovery_action_evidence,
)
from Virus_Scan.scheduler.queue.orphan_recovery_actions import requeue_reclaimed_active_job


class HostileBoundaryValue:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("called __str__")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("called __repr__")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("called __format__")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("called __bool__")

    def __int__(self):
        type(self).touched += 1
        raise AssertionError("called __int__")

    def __float__(self):
        type(self).touched += 1
        raise AssertionError("called __float__")

    def __fspath__(self):
        type(self).touched += 1
        raise AssertionError("called __fspath__")


class HostileMoveError(RuntimeError):
    def __str__(self):
        HostileBoundaryValue.touched += 1
        raise AssertionError("stringified move error")

    def __repr__(self):
        HostileBoundaryValue.touched += 1
        raise AssertionError("repr move error")

    def __format__(self, _spec):
        HostileBoundaryValue.touched += 1
        raise AssertionError("formatted move error")


def _base_args(tmp_path: Path, *, evidence: list, **overrides):
    active = tmp_path / "active"
    pending = tmp_path / "pending"
    active.mkdir()
    pending.mkdir()
    src = active / "job.json"
    src.write_text("{}", encoding="utf-8")
    args = dict(
        queue_dir=tmp_path,
        active_dir=active,
        pending_dir=pending,
        src=src,
        name="job.json",
        job={"file": "sample.bin"},
        queue_info={},
        now=100.0,
        attempt=0,
        info={"time": "2026-01-01T00:00:00Z"},
        evidence_records=evidence,
        cleanup_orphan_claim_meta=lambda *_args, **_kwargs: 0,
        process_queue_env_int=lambda *_args, **_kwargs: 0,
    )
    args.update(overrides)
    return args


def test_stage1897_orphan_action_evidence_uses_missing_text_not_fallback() -> None:
    record = orphan_recovery_action_evidence(OrphanRecoveryActionEvidenceRequest(
        stage="stage",
        action="move",
        source_path="active/job.json",
        destination_path="",
        error=RuntimeError("failed"),
        error_source="scheduler.queue.orphan_recovery_actions",
        job_id=None,
    )).as_record()

    assert record["job_id"] == "missing_orphan_job_id"
    assert record["destination_path"] == ""


def test_stage1897_reclaim_rejects_hostile_attempt_name_and_claim_meta_result_without_hooks(tmp_path: Path) -> None:
    evidence = []
    suppressed = []
    HostileBoundaryValue.touched = 0

    arguments = _base_args(
        tmp_path,
        evidence=evidence,
        attempt=HostileBoundaryValue(),
        name=HostileBoundaryValue(),
        safe_remove_claim_meta=lambda _path: HostileBoundaryValue(),
        record_suppressed=lambda where, exc, **kwargs: suppressed.append((where, exc, kwargs)),
    )
    Path(arguments["src"]).unlink()
    result = requeue_reclaimed_active_job(**arguments)

    assert result is None
    assert HostileBoundaryValue.touched == 0
    assert evidence[0]["stage"] == "process_queue_reclaim_active_move_rejected"
    assert "unsupported_reclaim_source_name" in evidence[0]["destination_path"]
    assert suppressed[0][0] == "process_queue_reclaim_pre_move_claim_meta_cleanup_incomplete"
    assert suppressed[0][2]["extra"]["source"].endswith("job.json")


def test_stage1897_reclaim_move_exception_logs_no_hook_detail(tmp_path: Path) -> None:
    evidence = []
    suppressed = []
    logs = []
    HostileBoundaryValue.touched = 0

    def failing_cleanup(*_args, **_kwargs):
        raise HostileMoveError("hidden move detail")

    result = requeue_reclaimed_active_job(
        **_base_args(
            tmp_path,
            evidence=evidence,
            safe_remove_claim_meta=lambda _path: True,
            cleanup_orphan_claim_meta=failing_cleanup,
            record_suppressed=lambda where, exc, **kwargs: suppressed.append((where, exc, kwargs)),
            log_error=logs.append,
        )
    )

    assert result is None
    assert HostileBoundaryValue.touched == 0
    assert evidence[0]["stage"] == "process_queue_reclaim_active_move_failed"
    assert suppressed[0][0] == "process_queue_reclaim_move_failed"
    assert "scheduler diagnostic detail unavailable" in logs[0]
