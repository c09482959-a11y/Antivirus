"""Replay comparison orchestration with projection-failure evidence."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scheduler.replay.replay_mismatch import build_replay_comparison_result
from Virus_Scan.scheduler.replay.replay_projection_failure import (
    REPLAY_PROJECTION_EXCEPTIONS,
    build_replay_projection_failure_comparison,
)


def _normalize_side(results: object, normalize: Callable[[object], object]) -> tuple[object, BaseException | None]:
    try:
        return normalize(results), None
    except REPLAY_PROJECTION_EXCEPTIONS as exc:
        return None, exc


def compare_with_projection_evidence(expected_results: object, actual_results: object, normalize: Callable[[object], object]) -> object:
    expected, expected_error = _normalize_side(expected_results, normalize)
    actual, actual_error = _normalize_side(actual_results, normalize)
    if expected_error is not None or actual_error is not None:
        return build_replay_projection_failure_comparison(
            expected_error=expected_error,
            expected_raw_results=expected_results,
            actual_error=actual_error,
            actual_raw_results=actual_results,
        )
    return build_replay_comparison_result(expected, actual)


def assert_with_projection_evidence(
    expected_results: object,
    actual_results: object,
    normalize: Callable[[object], object],
    mismatch_error: Callable[[object], BaseException],
) -> object:
    comparison = compare_with_projection_evidence(expected_results, actual_results, normalize)
    if not comparison.matched:
        raise mismatch_error(comparison)
    return normalize(actual_results)


__all__ = ("assert_with_projection_evidence", "compare_with_projection_evidence")
