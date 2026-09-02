from __future__ import annotations

from Virus_Scan.scheduler.replay.replay_validator import (
    QueueReplayComparisonRecord,
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


def test_stage830_scheduler_evidence_order_and_volatile_case_do_not_create_replay_delta() -> None:
    expected = _result(
        "job-a",
        "/tmp/corpus/a.bin",
        scheduler_evidence=[
            {"category": "queue_integrity", "Timestamp": 100, "PID": 111},
            {"category": "worker_failure", "Thread_ID": "left"},
        ],
    )
    actual = _result(
        "job-a",
        "/tmp/corpus/a.bin",
        scheduler_evidence=[
            {"Thread_ID": "right", "category": "worker_failure"},
            {"PID": 222, "category": "queue_integrity", "Timestamp": 200},
        ],
    )

    comparison = compare_scheduler_replay_results([expected], [actual])

    assert comparison.matched is True
    assert comparison.mismatches == ()


def test_stage830_scheduler_evidence_content_change_still_creates_replay_mismatch() -> None:
    comparison = compare_scheduler_replay_results(
        [_result("job-a", "/tmp/corpus/a.bin", scheduler_evidence=[{"category": "queue_integrity"}])],
        [_result("job-a", "/tmp/corpus/a.bin", scheduler_evidence=[{"category": "worker_failure"}])],
    )

    assert comparison.matched is False
    mismatch = next(item for item in comparison.mismatches if item["field"] == "scheduler_evidence")
    assert mismatch["error_category"] == "replay_mismatch"
    assert mismatch["final_json_must_record"] is True
    assert mismatch["checkpoint_must_record"] is True
    assert mismatch["replay_must_record"] is True


def test_stage830_direct_replay_record_scheduler_evidence_order_is_canonical() -> None:
    left = QueueReplayComparisonRecord(
        job_id="job-a",
        file_identity="file-a",
        verdict="Clean",
        tags=(),
        chains=(),
        engine_routing="renpy",
        duplicate_count=0,
        recovery_count=0,
        failed_count=0,
        scheduler_evidence=("b", "a", "b"),
    )
    right = QueueReplayComparisonRecord(
        job_id="job-a",
        file_identity="file-a",
        verdict="Clean",
        tags=(),
        chains=(),
        engine_routing="renpy",
        duplicate_count=0,
        recovery_count=0,
        failed_count=0,
        scheduler_evidence=("a", "b"),
    )

    assert left.scheduler_evidence == right.scheduler_evidence == ("a", "b")
