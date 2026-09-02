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


def test_stage828_dual_projection_failures_are_both_recorded() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", verdict="")],
        [_result("job-b", "/tmp/corpus/b.bin", file="")],
    )

    assert comparison.matched is False
    sides = {item["side"] for item in comparison.mismatches}
    assert sides == {"expected", "actual"}
    assert comparison.expected.evidence[0]["error_category"] == "replay_projection_failure"
    assert comparison.actual.evidence[0]["error_category"] == "replay_projection_failure"
    for mismatch in comparison.mismatches:
        assert mismatch["final_json_must_record"] is True
        assert mismatch["checkpoint_must_record"] is True
        assert mismatch["replay_must_record"] is True


def test_stage828_assertion_preserves_dual_projection_failure_comparison() -> None:
    with pytest.raises(SchedulerReplayMismatchError) as captured:
        assert_scheduler_replay_equivalent(
            [_result("job-a", "/tmp/corpus/a.bin", verdict="")],
            [_result("job-b", "/tmp/corpus/b.bin", file="")],
        )

    comparison = captured.value.comparison_result
    assert {item["side"] for item in comparison.mismatches} == {"expected", "actual"}


def test_stage828_dual_projection_failure_reaches_final_json_scheduler_evidence() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", verdict="")],
        [_result("job-b", "/tmp/corpus/b.bin", file="")],
    )

    scheduler = build_final_json_scheduler_section(
        {
            "file": "/tmp/corpus/a.bin",
            "replay_comparison_result": comparison.as_dict(),
        }
    )

    assert scheduler is not None
    assert scheduler["scheduler_status"] in {"degraded", "failure"}
    assert scheduler["replay_comparison_result"]["matched"] is False
    assert scheduler["evidence"][0]["error_category"] == "replay_mismatch"
    assert scheduler["evidence"][0]["context"]["mismatch_count"] == 2
