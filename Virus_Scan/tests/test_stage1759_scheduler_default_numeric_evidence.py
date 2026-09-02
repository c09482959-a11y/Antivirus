from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from Virus_Scan.scheduler.evidence.execution_event_support import scheduler_attempt_value
from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import load_active_claim_state
from Virus_Scan.scheduler.timeout.inmemory_timeout_numeric_policy import (
    safe_timeout_result_count,
)


@pytest.mark.parametrize("value", (True, -1, -0.5, 1.5))
def test_stage1759_invalid_execution_attempts_emit_field_evidence(value) -> None:
    attempt, issue = scheduler_attempt_value(value)

    assert attempt == 0
    assert issue is not None
    assert issue["scheduler_execution_field_rejected"] is True
    assert issue["field_name"] == "attempt"


@pytest.mark.parametrize("value", (True, -1, -0.5, 1.5))
def test_stage1759_invalid_timeout_counts_emit_reporting_evidence(value) -> None:
    failures = []

    count = safe_timeout_result_count(
        value=value,
        field="hard_timeouts",
        reporting_failures=failures,
    )

    assert count == 0
    assert len(failures) == 1
    assert failures[0]["reason"].startswith("hard_timeouts_")


def test_stage1759_corrupt_claim_timestamps_are_evidence_explicit(tmp_path: Path) -> None:
    active = tmp_path / "claim.json"
    active.write_text(
        json.dumps(
            {
                "file": "sample.bin",
                "queue_info": {
                    "claimed_time": -1,
                    "heartbeat_time": "not-a-time",
                    "progress_time": float("inf"),
                },
            }
        ),
        encoding="utf-8",
    )
    now = time.time()

    state = load_active_claim_state(
        active,
        now=now,
        stale=30.0,
        file_timeout=60.0,
        progress_stall=30.0,
        worker_liveness_checker=lambda *_args, **_kwargs: type("Liveness", (), {"alive": False})(),
    )

    assert state is not None
    assert state.claim_age >= 0.0
    assert {record["field"] for record in state.recovery_evidence} == {
        "claimed_time",
        "heartbeat_time",
        "progress_time",
    }
    assert all(record["final_json_must_record"] is True for record in state.recovery_evidence)
    assert all(record["checkpoint_must_record"] is True for record in state.recovery_evidence)
    assert all(record["replay_must_record"] is True for record in state.recovery_evidence)
