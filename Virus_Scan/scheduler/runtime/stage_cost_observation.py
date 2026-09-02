"""Scheduler stage-cost runtime pressure observation."""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import (
    get_runtime_economics_ledger,
    record_suppressed_failure,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
)


_STAGE_COST_HIGH_DURATION_SECONDS = 120.0
_STAGE_COST_MEDIUM_DURATION_SECONDS = 45.0
_STAGE_COST_LOW_DURATION_SECONDS = 15.0
_STAGE_COST_IDLE_DURATION_SECONDS = 3.0
_STAGE_COST_HIGH_RSS_MB = 2048.0
_STAGE_COST_MEDIUM_RSS_MB = 1024.0
_STAGE_COST_LOW_RSS_MB = 512.0
_STAGE_COST_IDLE_RSS_MB = 256.0


def _record_pressure_rejections(rejections: tuple[tuple[str, str], ...]) -> None:
    for where, reason in rejections:
        if reason:
            record_suppressed_failure(where, ValueError(reason), domain="scheduler")


def _duration_pressure(duration: float) -> float:
    if duration > _STAGE_COST_HIGH_DURATION_SECONDS:
        return 0.75
    if duration > _STAGE_COST_MEDIUM_DURATION_SECONDS:
        return 0.4
    if duration > _STAGE_COST_LOW_DURATION_SECONDS:
        return 0.15
    return 0.0


def _rss_pressure(rss_mb: float) -> float:
    if rss_mb > _STAGE_COST_HIGH_RSS_MB:
        return 0.75
    if rss_mb > _STAGE_COST_MEDIUM_RSS_MB:
        return 0.35
    if rss_mb > _STAGE_COST_LOW_RSS_MB:
        return 0.15
    return 0.0


def pressure_from_observation(
    duration_sec: object=0.0,
    rss_mb: object=0.0,
    *, stalled: object=False,
    retried: object=False,
) -> object:
    dur, duration_reason = scheduler_float(
        duration_sec,
        default=_STAGE_COST_HIGH_DURATION_SECONDS,
        minimum=0.0,
        reason="scheduler_stage_duration_rejected",
    )
    rss, rss_reason = scheduler_float(
        rss_mb,
        default=_STAGE_COST_HIGH_RSS_MB,
        minimum=0.0,
        reason="scheduler_stage_rss_rejected",
    )
    stalled_flag, stalled_reason = scheduler_bool(
        stalled,
        default=True,
        reason="scheduler_stage_stalled_flag_rejected",
    )
    retried_flag, retried_reason = scheduler_bool(
        retried,
        default=True,
        reason="scheduler_stage_retried_flag_rejected",
    )
    _record_pressure_rejections((
        ("stage_duration_rejected", duration_reason),
        ("stage_rss_rejected", rss_reason),
        ("stage_stalled_flag_rejected", stalled_reason),
        ("stage_retried_flag_rejected", retried_reason),
    ))
    pressure = 1.0 + _duration_pressure(dur) + _rss_pressure(rss)
    if stalled_flag:
        pressure += 0.5
    if retried_flag:
        pressure += 0.35
    if dur < _STAGE_COST_IDLE_DURATION_SECONDS and rss < _STAGE_COST_IDLE_RSS_MB and not stalled_flag and not retried_flag:
        pressure -= 0.1
    return max(0.75, min(3.0, pressure))


def observe_runtime_execution_cost(
    duration_sec: object=0.0,
    rss_mb: object=0.0,
    *, stalled: object=False,
    retried: object=False,
) -> object:
    try:
        duration, duration_reason = scheduler_float(
            duration_sec,
            default=_STAGE_COST_HIGH_DURATION_SECONDS,
            minimum=0.0,
            reason="scheduler_stage_duration_rejected",
        )
        rss, rss_reason = scheduler_float(
            rss_mb,
            default=_STAGE_COST_HIGH_RSS_MB,
            minimum=0.0,
            reason="scheduler_stage_rss_rejected",
        )
        stalled_flag, stalled_reason = scheduler_bool(
            stalled,
            default=True,
            reason="scheduler_stage_stalled_flag_rejected",
        )
        retried_flag, retried_reason = scheduler_bool(
            retried,
            default=True,
            reason="scheduler_stage_retried_flag_rejected",
        )
        reason = (
            duration_reason
            or rss_reason
            or stalled_reason
            or retried_reason
        )
        if reason:
            record_suppressed_failure(
                "stage_execution_cost_input_rejected",
                ValueError(reason),
                domain="scheduler",
            )
        get_runtime_economics_ledger().observe(
            "execution_cost",
            duration
            + (rss / 1024.0)
            + (1.0 if stalled_flag else 0.0)
            + (0.5 if retried_flag else 0.0),
        )
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_suppressed_failure(
            "stage_execution_cost_observe_failed",
            exc,
            domain="scheduler",
        )


__all__ = ("observe_runtime_execution_cost", "pressure_from_observation")
