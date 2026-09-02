from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.orphan_recovery_failure_info import build_reclaim_failure_info


class Stage2196HostilePid:
    touched = 0

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid string hook executed")

    def __int__(self) -> int:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid int hook executed")


class Stage2196HostileTermination:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("termination iteration hook executed")

    def __bool__(self) -> bool:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("termination bool hook executed")


def test_stage2196_orphan_recovery_failure_info_has_no_any_boundary_annotations() -> None:
    source = Path("Virus_Scan/scheduler/queue/orphan_recovery_failure_info.py").read_text(encoding="utf-8")

    assert "typing import Any" not in source
    assert "Any" not in source
    assert "object" in source


def test_stage2196_orphan_recovery_failure_info_keeps_no_hook_failure_evidence() -> None:
    Stage2196HostilePid.touched = 0
    Stage2196HostileTermination.touched = 0

    info = build_reclaim_failure_info(
        reason_stage="queue_worker_orphaned",
        timeout_expired=False,
        hard_file_timeout=30.0,
        file_timeout=15.0,
        checkpoint_stalled=True,
        progress_age=9.5,
        hb_age=2.0,
        claim_age=3.0,
        pid=Stage2196HostilePid(),
        pid_alive=False,
        heartbeat_fresh=False,
        timeout_evidence={"stage2196": "timeout"},
        owner_killed=False,
        termination_evidence=Stage2196HostileTermination(),
        recovered=True,
        attempt=2,
        now_text="2026-06-28T00:00:00Z",
        progress_marker={"marker": "owned"},
    )

    assert info["exception_type"] == "ProgressStalled"
    assert info["worker_pid"] == {"worker_pid_unavailable": True, "value_type": "Stage2196HostilePid"}
    assert info["worker_termination"] == {
        "worker_termination_unavailable": True,
        "value_type": "Stage2196HostileTermination",
    }
    assert info["timeout_evidence"] == {"stage2196": "timeout"}
    assert info["progress_marker"] == {"marker": "owned"}
    assert Stage2196HostilePid.touched == 0
    assert Stage2196HostileTermination.touched == 0
