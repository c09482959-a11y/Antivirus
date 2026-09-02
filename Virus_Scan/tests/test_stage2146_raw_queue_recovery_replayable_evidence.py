from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_recovery import _last_state, _path_key, _raw_count_total, raw_stage_progress_recent
from Virus_Scan.scheduler.queue.raw_queue_recovery_evidence import (
    RawStageProgressCountEvidence,
    RawStageProgressPathKey,
    RawStageProgressStateEvidence,
)


class HostileValue:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile bool hook touched")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile str hook touched")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile repr hook touched")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile int hook touched")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile float hook touched")

    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile fspath hook touched")


def test_stage2146_raw_queue_recovery_path_rejection_returns_replayable_evidence() -> None:
    HostileValue.touched = 0
    reports: list[tuple[str, str]] = []

    evidence = _path_key(HostileValue(), lambda where, exc: reports.append((where, str(exc))))

    assert evidence == RawStageProgressPathKey("", False, "scheduler_path_rejected")
    assert reports == [("raw_stage_progress_queue_dir_rejected", "scheduler_path_rejected")]
    assert HostileValue.touched == 0


def test_stage2146_raw_queue_recovery_count_rejection_returns_typed_evidence() -> None:
    reports: list[tuple[str, str]] = []

    evidence = _raw_count_total(HostileValue(), lambda where, exc: reports.append((where, str(exc))))

    assert evidence == RawStageProgressCountEvidence(0, False, "raw_stage_progress_counts_rejected")
    assert reports == [("raw_stage_progress_count_failed", "raw_stage_progress_counts_rejected")]


def test_stage2146_raw_queue_recovery_state_rejection_returns_typed_evidence() -> None:
    reports: list[tuple[str, str]] = []

    evidence = _last_state(HostileValue(), "queue", 123.0, lambda where, exc: reports.append((where, str(exc))))

    assert evidence == RawStageProgressStateEvidence(None, 123.0, False, "raw_stage_progress_state_rejected")
    assert reports == [("raw_stage_progress_state_rejected", "raw_stage_progress_state_rejected")]


def test_stage2146_raw_queue_recovery_public_behavior_preserves_safe_fallback(tmp_path: Path) -> None:
    reports: list[tuple[str, str]] = []

    assert raw_stage_progress_recent(
        tmp_path,
        quiet_sec=15,
        progress_counts=lambda _queue_dir: HostileValue(),
        queue_now=lambda: 100.0,
        state={},
        report=lambda where, exc: reports.append((where, str(exc))),
    ) is True

    assert ("raw_stage_progress_count_failed", "raw_stage_progress_counts_rejected") in reports
    assert HostileValue.touched == 0
