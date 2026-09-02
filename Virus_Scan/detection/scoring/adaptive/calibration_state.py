"""Owned adaptive scoring state for rolling fusion calibration."""
from __future__ import annotations

from collections import deque
from threading import RLock


class FusionScoreHistory:
    """Bounded, lock-owned score history for percentile calibration."""

    def __init__(self, *, maxlen: int = 1000) -> None:
        self._lock = RLock()
        self._values: deque[float] = deque(maxlen=int(maxlen))

    def add(self, score: float) -> tuple[float, ...]:
        with self._lock:
            self._values.append(float(score))
            return tuple(self._values)

    def snapshot(self) -> tuple[float, ...]:
        with self._lock:
            return tuple(self._values)


_FUSION_SCORE_HISTORY = FusionScoreHistory(maxlen=1000)


def record_fusion_score(score: float) -> tuple[float, ...]:
    return _FUSION_SCORE_HISTORY.add(score)


def fusion_score_history_snapshot() -> tuple[float, ...]:
    return _FUSION_SCORE_HISTORY.snapshot()


__all__ = ("FusionScoreHistory", "fusion_score_history_snapshot", "record_fusion_score")
