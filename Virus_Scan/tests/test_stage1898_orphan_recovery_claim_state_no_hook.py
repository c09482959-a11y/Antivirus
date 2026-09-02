from __future__ import annotations

import json
import time
from pathlib import Path

from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import _claim_numeric, load_active_claim_state
from Virus_Scan.scheduler.queue.orphan_recovery_failure_info import build_reclaim_failure_info


class HostileField:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("field string hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("field repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("field format hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("field truth hook executed")


class HostileNumber:
    touched = 0

    def __float__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("numeric float hook executed")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("numeric string hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("numeric truth hook executed")


class HostileLiveness:
    touched = 0

    @property
    def alive(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid liveness property hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid liveness truth hook executed")


class HostileText(str):
    touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid truth hook executed")


def test_stage1898_claim_numeric_rejects_hostile_field_without_format_hooks() -> None:
    HostileField.touched = 0
    HostileNumber.touched = 0

    metric, issue = _claim_numeric(HostileNumber(), field=HostileField(), default=7.0)

    assert metric == 7.0
    assert issue is not None
    assert issue["error_category"] == "claim_numeric_malformed"
    assert issue["field"] == "claim_numeric"
    assert issue["value_type"] == "HostileNumber"
    assert HostileField.touched == 0
    assert HostileNumber.touched == 0


def test_stage1898_claim_numeric_negative_reason_is_owned_without_field_format() -> None:
    HostileField.touched = 0

    metric, issue = _claim_numeric(-1.0, field=HostileField(), default=3.0)

    assert metric == 3.0
    assert issue is not None
    assert issue["error_category"] == "claim_numeric_negative"
    assert issue["field"] == "claim_numeric"
    assert HostileField.touched == 0


def test_stage1898_load_active_claim_state_does_not_read_liveness_property(tmp_path: Path) -> None:
    HostileLiveness.touched = 0
    HostileText.touched = 0
    active = tmp_path / "active.json"
    active.write_text(
        json.dumps(
            {
                "worker_pid": "fallback-pid",
                "queue_info": {
                    "claimed_time": 10.0,
                    "heartbeat_time": 10.0,
                    "progress_time": 10.0,
                    "worker_pid": HostileText("123"),
                },
            }
        ),
        encoding="utf-8",
    )

    state = load_active_claim_state(
        active,
        now=time.time() + 120.0,
        stale=30.0,
        file_timeout=60.0,
        progress_stall=30.0,
        worker_liveness_checker=lambda *_args, **_kwargs: HostileLiveness(),
    )

    assert state is not None
    assert state.pid_alive is False
    assert state.heartbeat_fresh is False
    assert HostileLiveness.touched == 0
    assert HostileText.touched == 0


class HostilePid:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid string hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid format hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid truth hook executed")

    def __int__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("pid int hook executed")


class HostileTerminationEvidence:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("termination iteration hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("termination truth hook executed")


def test_stage1898_reclaim_failure_info_rejects_hostile_pid_and_termination_without_hooks() -> None:
    HostilePid.touched = 0
    HostileTerminationEvidence.touched = 0

    info = build_reclaim_failure_info(
        reason_stage="stage",
        timeout_expired=True,
        hard_file_timeout=90.0,
        file_timeout=60.0,
        checkpoint_stalled=False,
        progress_age=40.0,
        hb_age=35.0,
        claim_age=100.0,
        pid=HostilePid(),
        pid_alive=False,
        heartbeat_fresh=False,
        timeout_evidence={"kind": "timeout"},
        owner_killed=False,
        termination_evidence=HostileTerminationEvidence(),
        recovered=False,
        attempt=1,
        now_text="now",
        progress_marker={"marker": "owned"},
    )

    assert info["exception_type"] == "HardTimeout"
    assert "worker_pid=unsupported_pid_type_HostilePid" in info["error"]
    assert info["worker_pid"] == {"worker_pid_unavailable": True, "value_type": "HostilePid"}
    assert info["worker_termination"] == {"worker_termination_unavailable": True, "value_type": "HostileTerminationEvidence"}
    assert HostilePid.touched == 0
    assert HostileTerminationEvidence.touched == 0
