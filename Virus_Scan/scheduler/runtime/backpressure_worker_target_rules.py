"""Bounded worker-target rules for scheduler runtime backpressure."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from Virus_Scan.contracts.env_config import int_env
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int

_SCHEDULER_BACKPRESSURE_INTEGER_REJECTED: Final = (
    "scheduler_backpressure_integer_rejected"
)
_DEFAULT_IO_TARGET_WORKERS: Final = 48
_DEFAULT_RAW_LIVE_SOFT_CAP: Final = 1000
_EXTREME_RAW_LIVE_MIN_TARGET: Final = 8
_HIGH_RAW_LIVE_MIN_TARGET: Final = 12
_SOFT_RAW_LIVE_MIN_TARGET: Final = 16
_EXTREME_RAW_LIVE_RATIO: Final = 0.54
_HIGH_RAW_LIVE_RATIO: Final = 0.68
_SOFT_RAW_LIVE_RATIO: Final = 0.8
_HIGH_CPU_TARGET_RULES: Final = (
    (65.0, 1.0),
    (78.0, 0.96),
    (88.0, 0.88),
    (94.0, 0.72),
    (98.0, 0.56),
    (99.5, 0.4),
)
_HIGH_CPU_SATURATED_RATIO: Final = 0.28


@dataclass(frozen=True, slots=True)
class RawLiveCapThresholds:
    """Raw-live pressure thresholds used by the elastic worker target curve."""

    soft: int
    high: int
    extreme: int


def positive_worker_count(value: object, *, default: int) -> int:
    """Materialize a positive scheduler worker count without caller hooks."""

    safe, _reason = scheduler_int(
        value,
        default=default,
        minimum=1,
        reason=_SCHEDULER_BACKPRESSURE_INTEGER_REJECTED,
    )
    return safe


def nonnegative_raw_live(value: object) -> int:
    """Materialize a non-negative raw-live count without caller hooks."""

    safe, _reason = scheduler_int(
        value,
        default=0,
        minimum=0,
        reason=_SCHEDULER_BACKPRESSURE_INTEGER_REJECTED,
    )
    return safe


def clamp_worker_target(value: object, *, max_workers: int) -> int:
    """Clamp a candidate worker target to the active worker bound."""

    candidate = positive_worker_count(value, default=1)
    return max(1, min(max_workers, candidate))


def raw_live_cap_thresholds() -> RawLiveCapThresholds:
    """Return configured raw-live pressure thresholds."""

    soft = int_env("UMIGE_RAW_LIVE_SOFT_CAP", _DEFAULT_RAW_LIVE_SOFT_CAP, 1, None)
    high = int_env("UMIGE_RAW_LIVE_HIGH_CAP", soft * 2, 1, None)
    extreme = int_env("UMIGE_RAW_LIVE_EXTREME_CAP", high * 2, 1, None)
    return RawLiveCapThresholds(soft=soft, high=high, extreme=extreme)


def io_pressure_worker_target(*, max_workers: int) -> int:
    """Return the configured worker target while explicit I/O pressure is active."""

    return clamp_worker_target(
        int_env("UMIGE_ELASTIC_IO_TARGET_WORKERS", _DEFAULT_IO_TARGET_WORKERS, 1, None),
        max_workers=max_workers,
    )



def raw_live_worker_target(
    raw_live: int,
    *,
    max_workers: int,
    thresholds: RawLiveCapThresholds,
) -> int | None:
    """Return a raw-live pressure target, or None when CPU rules should decide."""

    if raw_live > thresholds.extreme:
        return clamp_worker_target(
            max(_EXTREME_RAW_LIVE_MIN_TARGET, int(max_workers * _EXTREME_RAW_LIVE_RATIO)),
            max_workers=max_workers,
        )
    if raw_live > thresholds.high:
        return clamp_worker_target(
            max(_HIGH_RAW_LIVE_MIN_TARGET, int(max_workers * _HIGH_RAW_LIVE_RATIO)),
            max_workers=max_workers,
        )
    if raw_live > thresholds.soft:
        return clamp_worker_target(
            max(_SOFT_RAW_LIVE_MIN_TARGET, int(max_workers * _SOFT_RAW_LIVE_RATIO)),
            max_workers=max_workers,
        )
    return None


def cpu_pressure_worker_target(cpu_pct: float | None, *, max_workers: int) -> int:
    """Return the high-profile CPU pressure worker target."""

    if cpu_pct is None:
        return clamp_worker_target(max_workers, max_workers=max_workers)
    for threshold, ratio in _HIGH_CPU_TARGET_RULES:
        if cpu_pct < threshold:
            return clamp_worker_target(max_workers * ratio, max_workers=max_workers)
    return clamp_worker_target(
        max_workers * _HIGH_CPU_SATURATED_RATIO,
        max_workers=max_workers,
    )


__all__ = (
    "RawLiveCapThresholds",
    "clamp_worker_target",
    "cpu_pressure_worker_target",
    "io_pressure_worker_target",
    "nonnegative_raw_live",
    "positive_worker_count",
    "raw_live_cap_thresholds",
    "raw_live_worker_target",
)
