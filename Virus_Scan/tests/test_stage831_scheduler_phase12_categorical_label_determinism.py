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


def test_stage831_replay_verdict_and_engine_case_do_not_create_false_mismatch() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", verdict="Clean", engine="RenPy")],
        [_result("job-a", "/tmp/corpus/a.bin", verdict="clean", engine="renpy")],
    )

    assert comparison.matched is True
    assert comparison.mismatches == ()


def test_stage831_replay_verdict_content_change_still_creates_mismatch() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", verdict="Clean", engine="renpy")],
        [_result("job-a", "/tmp/corpus/a.bin", verdict="Malicious", engine="renpy")],
    )

    assert comparison.matched is False
    mismatch = next(item for item in comparison.mismatches if item["field"] == "verdict")
    assert mismatch["expected"] == "clean"
    assert mismatch["actual"] == "malicious"
    assert mismatch["final_json_must_record"] is True
    assert mismatch["checkpoint_must_record"] is True
    assert mismatch["replay_must_record"] is True


def test_stage831_replay_engine_content_change_still_creates_mismatch() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", verdict="Clean", engine="renpy")],
        [_result("job-a", "/tmp/corpus/a.bin", verdict="Clean", engine="unity")],
    )

    assert comparison.matched is False
    mismatch = next(item for item in comparison.mismatches if item["field"] == "engine_routing")
    assert mismatch["expected"] == "renpy"
    assert mismatch["actual"] == "unity"
    assert mismatch["error_category"] == "replay_mismatch"
