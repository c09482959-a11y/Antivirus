"""Canonical scheduler timeout authority boundaries.

This module owns immutable timeout authority snapshots and configured hard-wall
budget boundaries. It does not monitor heartbeats, mutate queues, kill workers,
or serialize evidence; enforcement remains in scheduler.timeout owners.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_text


@dataclass(frozen=True, slots=True)
class TimeoutAuthoritySnapshot:
    """Immutable timeout authority decision for one scheduler file job."""

    configured_hard_timeout_seconds: float
    minimum_hard_timeout_seconds: float = 30.0
    maximum_hard_timeout_seconds: float = 86400.0
    source: str = "scheduler_request"

    def configured_floor(self) -> float:
        configured, _configured_reason = scheduler_float(self.configured_hard_timeout_seconds, default=0.0, minimum=0.0)
        maximum, _maximum_reason = scheduler_float(self.maximum_hard_timeout_seconds, default=86400.0, minimum=0.0)
        return max(0.0, min(maximum, configured))

    def clamp_hard_budget(self, seconds: float) -> float:
        floor = self.configured_floor()
        minimum, _minimum_reason = scheduler_float(self.minimum_hard_timeout_seconds, default=30.0, minimum=0.0)
        maximum, _maximum_reason = scheduler_float(self.maximum_hard_timeout_seconds, default=86400.0, minimum=minimum)
        seconds_value, _seconds_reason = scheduler_float(seconds, default=0.0, minimum=0.0)
        value = max(minimum, seconds_value, floor)
        return min(maximum, value)

    def as_evidence(self) -> Mapping[str, object]:
        return {
            "timeout_authority_source": self.source,
            "configured_hard_timeout_seconds": self.configured_floor(),
            "minimum_hard_timeout_seconds": scheduler_float(self.minimum_hard_timeout_seconds, default=30.0, minimum=0.0)[0],
            "maximum_hard_timeout_seconds": scheduler_float(self.maximum_hard_timeout_seconds, default=86400.0, minimum=0.0)[0],
        }


def build_timeout_authority_snapshot(
    configured_seconds: float | str | None,
    *,
    minimum_hard_timeout_seconds: float = 30.0,
    maximum_hard_timeout_seconds: float = 86400.0,
    source: str = "scheduler_request",
) -> TimeoutAuthoritySnapshot:
    """Build a deterministic immutable timeout authority snapshot."""
    configured, _configured_reason = scheduler_float(configured_seconds, default=0.0, minimum=0.0)
    minimum, _minimum_reason = scheduler_float(minimum_hard_timeout_seconds, default=30.0, minimum=0.0)
    maximum, _maximum_reason = scheduler_float(maximum_hard_timeout_seconds, default=86400.0, minimum=minimum)
    source_text, source_reason = scheduler_text(
        source,
        unsupported_reason="timeout_authority_source_rejected",
    )
    if source_reason or not source_text:
        source_text = "scheduler_request"
    return TimeoutAuthoritySnapshot(
        configured_hard_timeout_seconds=min(configured, maximum),
        minimum_hard_timeout_seconds=minimum,
        maximum_hard_timeout_seconds=maximum,
        source=source_text,
    )


def build_timeout_authority_from_runtime(
    runtime_value: Callable[..., object],
    *,
    configured_seconds: float | str | None,
    source: str = "scheduler_request",
) -> TimeoutAuthoritySnapshot:
    """Build authority using explicit runtime-owned max boundary configuration."""
    try:
        maximum_raw = runtime_value("SCHEDULER_HARD_TIMEOUT_MAX_SECONDS", 86400.0)
    except (TypeError, ValueError, RuntimeError, OverflowError):
        maximum_raw = 86400.0
    maximum, _maximum_reason = scheduler_float(maximum_raw, default=86400.0, minimum=0.0)
    return build_timeout_authority_snapshot(
        configured_seconds,
        maximum_hard_timeout_seconds=maximum,
        source=source,
    )


__all__ = (
    "TimeoutAuthoritySnapshot",
    "build_timeout_authority_from_runtime",
    "build_timeout_authority_snapshot",
)
