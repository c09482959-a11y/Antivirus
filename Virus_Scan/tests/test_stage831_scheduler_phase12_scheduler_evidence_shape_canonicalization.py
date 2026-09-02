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


def test_stage831_single_mapping_and_one_item_evidence_list_are_replay_equivalent() -> None:
    expected = _result(
        "job-a",
        "/tmp/corpus/a.bin",
        scheduler_evidence={"category": "queue_integrity", "Timestamp": 100},
    )
    actual = _result(
        "job-a",
        "/tmp/corpus/a.bin",
        scheduler_evidence=[{"category": "queue_integrity", "Timestamp": 200}],
    )

    comparison = compare_scheduler_replay_results([expected], [actual])

    assert comparison.matched is True
    assert comparison.mismatches == ()


def test_stage831_nested_scheduler_evidence_sources_are_flattened_and_deduplicated() -> None:
    expected = _result(
        "job-a",
        "/tmp/corpus/a.bin",
        scheduler_evidence=[
            [{"category": "worker_failure", "PID": 123}],
            {"category": "queue_integrity"},
        ],
    )
    actual = _result(
        "job-a",
        "/tmp/corpus/a.bin",
        scheduler={
            "scheduler_failure_evidence": [
                {"category": "queue_integrity"},
                [{"category": "worker_failure", "PID": 456}],
            ]
        },
    )

    comparison = compare_scheduler_replay_results([expected], [actual])

    assert comparison.matched is True
    assert comparison.mismatches == ()


def test_stage831_scheduler_evidence_shape_canonicalization_preserves_content_mismatch() -> None:
    comparison = compare_scheduler_replay_results(
        [
            _result(
                "job-a",
                "/tmp/corpus/a.bin",
                scheduler_evidence={"category": "queue_integrity"},
            )
        ],
        [
            _result(
                "job-a",
                "/tmp/corpus/a.bin",
                scheduler_evidence=[{"category": "worker_failure"}],
            )
        ],
    )

    assert comparison.matched is False
    mismatch = next(item for item in comparison.mismatches if item["field"] == "scheduler_evidence")
    assert mismatch["error_category"] == "replay_mismatch"
    assert mismatch["final_json_must_record"] is True
    assert mismatch["checkpoint_must_record"] is True
    assert mismatch["replay_must_record"] is True
