from __future__ import annotations

from Virus_Scan.scheduler.replay.replay_validator import compare_scheduler_replay_results


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


def test_stage829_tag_order_does_not_create_replay_delta() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", tags=["beta", "alpha", "beta"])],
        [_result("job-a", "/tmp/corpus/a.bin", tags=["alpha", "beta"])],
    )

    assert comparison.matched is True
    assert comparison.mismatches == ()


def test_stage829_chain_order_does_not_create_replay_delta() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", chains=["late", "early"])],
        [_result("job-a", "/tmp/corpus/a.bin", chains=["early", "late"])],
    )

    assert comparison.matched is True
    assert comparison.mismatches == ()


def test_stage829_tag_content_still_creates_explicit_replay_mismatch() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", tags=["alpha", "beta"])],
        [_result("job-a", "/tmp/corpus/a.bin", tags=["alpha", "gamma"])],
    )

    assert comparison.matched is False
    assert any(item["field"] == "tags" for item in comparison.mismatches)
    mismatch = next(item for item in comparison.mismatches if item["field"] == "tags")
    assert mismatch["error_category"] == "replay_mismatch"
    assert mismatch["final_json_must_record"] is True
    assert mismatch["checkpoint_must_record"] is True
    assert mismatch["replay_must_record"] is True
