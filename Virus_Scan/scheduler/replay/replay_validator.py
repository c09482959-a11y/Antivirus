"""Canonical scheduler replay validation ownership."""

from __future__ import annotations

from Virus_Scan.scheduler.replay.replay_projection_compare import (
    assert_with_projection_evidence,
    compare_with_projection_evidence,
)
from Virus_Scan.scheduler.replay.replay_mismatch import (
    QueueReplayComparisonRecord,
    QueueReplayComparisonSnapshot,
    SchedulerReplayMismatchError,
)

def normalize_scheduler_replay_results(results: object) -> QueueReplayComparisonSnapshot:
    """Project scheduler results into a deterministic replay-comparison snapshot."""
    return QueueReplayComparisonSnapshot.from_results(results)

def compare_scheduler_replay_results(expected_results: object, actual_results: object) -> object:
    """Return immutable replay comparison evidence without mutating scheduler state."""
    return compare_with_projection_evidence(
        expected_results,
        actual_results,
        normalize_scheduler_replay_results,
    )

def assert_scheduler_replay_equivalent(expected_results: object, actual_results: object) -> QueueReplayComparisonSnapshot:
    """Hard-fail when replay changes scheduler forensic outcomes."""
    return assert_with_projection_evidence(
        expected_results,
        actual_results,
        normalize_scheduler_replay_results,
        SchedulerReplayMismatchError,
    )



__all__ = (
    "QueueReplayComparisonRecord",
    "QueueReplayComparisonSnapshot",
    "SchedulerReplayMismatchError",
    "assert_scheduler_replay_equivalent",
    "compare_scheduler_replay_results",
    "normalize_scheduler_replay_results",
)
