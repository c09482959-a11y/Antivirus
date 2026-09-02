"""Detection-owned calibration math helpers."""

from __future__ import annotations

import math


def sigmoid01(x: float, midpoint: float = 2.0, scale: float = 0.8) -> float:
    return 1.0 / (1.0 + math.exp(-((float(x) - midpoint) / max(0.05, float(scale)))))


__all__ = ("sigmoid01",)
