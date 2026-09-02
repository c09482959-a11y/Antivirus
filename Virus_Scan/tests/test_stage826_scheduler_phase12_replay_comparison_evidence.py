from __future__ import annotations

import pytest

from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section
from Virus_Scan.scheduler.replay.replay_validator import (
    SchedulerReplayMismatchError,
    assert_scheduler_replay_equivalent,
    compare_scheduler_replay_results,
)


def _result(job_id: str, file_path: str, **overrides):
    result = {
        "job_id": job_id,
        "file": file_path,
        "verdict": "Clean",
        "tags": ["stable"],
        "chains": ["chain"],
        "engine": "renpy",
    }
    result.update(overrides)
    return result


def test_stage826_replay_comparison_returns_immutable_mismatch_evidence() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", verdict="Clean")],
        [_result("job-a", "/tmp/corpus/a.bin", verdict="Malicious")],
    )

    assert comparison.matched is False
    assert comparison.mismatches
    mismatch = comparison.mismatches[0]
    assert mismatch["mismatch_type"] == "field_mismatch"
    assert mismatch["field"] == "verdict"
    assert mismatch["final_json_must_record"] is True
    assert mismatch["checkpoint_must_record"] is True
    assert mismatch["replay_must_record"] is True

    with pytest.raises(Exception):
        comparison.mismatches = ()  # type: ignore[misc]


def test_stage826_replay_assertion_exposes_comparison_result_for_json_evidence() -> None:
    with pytest.raises(SchedulerReplayMismatchError) as captured:
        assert_scheduler_replay_equivalent(
            [_result("job-a", "/tmp/corpus/a.bin", verdict="Clean")],
            [_result("job-a", "/tmp/corpus/a.bin", verdict="Malicious")],
        )

    comparison = captured.value.comparison_result
    scheduler = build_final_json_scheduler_section(
        {
            "file": "/tmp/corpus/a.bin",
            "replay_comparison_result": comparison.as_dict(),
        }
    )

    assert scheduler is not None
    assert scheduler["scheduler_status"] in {"degraded", "failure"}
    assert scheduler["evidence"][0]["error_category"] == "replay_mismatch"
    assert scheduler["evidence"][0]["replay_must_record"] is True


def test_stage826_replay_comparison_detects_scheduler_evidence_drift() -> None:
    expected = [
        _result(
            "job-a",
            "/tmp/corpus/a.bin",
            scheduler={"evidence": [{"stage": "retry", "error_category": "retry_exhaustion"}]},
        )
    ]
    actual = [
        _result(
            "job-a",
            "/tmp/corpus/a.bin",
            scheduler={"evidence": [{"stage": "retry", "error_category": "worker_timeout"}]},
        )
    ]

    comparison = compare_scheduler_replay_results(expected, actual)

    assert comparison.matched is False
    assert any(item["field"] == "scheduler_evidence" for item in comparison.mismatches)


def test_stage826_replay_evidence_order_is_canonical_and_not_nondeterministic() -> None:
    left = [
        _result(
            "job-a",
            "/tmp/corpus/a.bin",
            scheduler={
                "evidence": [
                    {"stage": "queue", "error_category": "queue_integrity"},
                    {"stage": "worker", "error_category": "worker_timeout"},
                ]
            },
        )
    ]
    right = [
        _result(
            "job-a",
            "/tmp/corpus/a.bin",
            scheduler={
                "evidence": [
                    {"stage": "worker", "error_category": "worker_timeout"},
                    {"stage": "queue", "error_category": "queue_integrity"},
                ]
            },
        )
    ]

    comparison = compare_scheduler_replay_results(left, right)

    assert comparison.matched is True
    assert comparison.mismatches == ()
