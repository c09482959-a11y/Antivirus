from __future__ import annotations

import pytest

from Virus_Scan.scheduler.api.contracts import HybridQueueStateError
from Virus_Scan.scheduler.replay.replay_snapshot import validate_hybrid_counts
from Virus_Scan.scheduler.replay.replay_validator import compare_scheduler_replay_results


def _replay_result(count) -> dict[str, object]:
    return {
        "job_id": "job-1",
        "file": "sample.bin",
        "classification": "clean",
        "duplicate_count": count,
    }


@pytest.mark.parametrize("count", (True, -1, -0.5, 1.5))
def test_stage1758_invalid_replay_counts_become_projection_failure_evidence(count) -> None:
    comparison = compare_scheduler_replay_results(
        [_replay_result(0)],
        [_replay_result(count)],
    )

    assert comparison.matched is False
    assert comparison.actual.evidence[0]["error_category"] == "replay_projection_failure"
    assert comparison.mismatches[0]["error_category"] == "replay_projection_failure"


@pytest.mark.parametrize("count", (True, -1, -0.5, 1.5))
def test_stage1758_invalid_hybrid_snapshot_counts_are_rejected(count) -> None:
    with pytest.raises(HybridQueueStateError, match="invalid hybrid queue count value"):
        validate_hybrid_counts({"pending": count})


def test_stage1758_exact_scheduler_counts_remain_valid() -> None:
    assert dict(validate_hybrid_counts({"pending": 2.0, "done": "3"})) == {
        "done": 3,
        "pending": 2,
    }
    comparison = compare_scheduler_replay_results(
        [_replay_result(2.0)],
        [_replay_result("2")],
    )
    assert comparison.matched is True
