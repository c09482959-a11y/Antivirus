from __future__ import annotations

import pytest

from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section
from Virus_Scan.scheduler.replay.replay_validator import (
    SchedulerReplayMismatchError,
    assert_scheduler_replay_equivalent,
    compare_scheduler_replay_results,
)


def _result(job_id: str, file_path: str, **overrides):
    payload = {
        "job_id": job_id,
        "file": file_path,
        "verdict": "Clean",
        "tags": ["stable"],
        "chains": ["chain"],
        "engine": "renpy",
    }
    payload.update(overrides)
    return payload


def test_stage827_actual_projection_failure_returns_replay_comparison_evidence() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin")],
        [_result("job-a", "/tmp/corpus/a.bin", verdict="")],
    )

    assert comparison.matched is False
    mismatch = comparison.mismatches[0]
    assert mismatch["mismatch_type"] == "projection_failure"
    assert mismatch["side"] == "actual"
    assert mismatch["error_category"] == "replay_projection_failure"
    assert mismatch["final_json_must_record"] is True
    assert mismatch["checkpoint_must_record"] is True
    assert mismatch["replay_must_record"] is True
    assert comparison.actual.evidence[0]["error_category"] == "replay_projection_failure"


def test_stage827_expected_projection_failure_is_exposed_by_assertion() -> None:
    with pytest.raises(SchedulerReplayMismatchError) as captured:
        assert_scheduler_replay_equivalent(
            [_result("job-a", "/tmp/corpus/a.bin", file="")],
            [_result("job-a", "/tmp/corpus/a.bin")],
        )

    comparison = captured.value.comparison_result
    assert comparison.matched is False
    assert comparison.mismatches[0]["side"] == "expected"
    assert comparison.expected.evidence[0]["checkpoint_must_record"] is True


def test_stage827_projection_failure_reaches_final_json_scheduler_evidence() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin")],
        [_result("job-a", "/tmp/corpus/a.bin", verdict="")],
    )

    scheduler = build_final_json_scheduler_section(
        {
            "file": "/tmp/corpus/a.bin",
            "replay_comparison_result": comparison.as_dict(),
        }
    )

    assert scheduler is not None
    assert scheduler["scheduler_status"] in {"degraded", "failure"}
    evidence = scheduler["evidence"]
    assert evidence[0]["error_category"] == "replay_mismatch"
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["checkpoint_must_record"] is True
    assert evidence[0]["replay_must_record"] is True
