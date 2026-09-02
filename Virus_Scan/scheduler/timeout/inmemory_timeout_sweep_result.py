"""Immutable result contract for in-memory timeout sweeps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.timeout.inmemory_timeout_numeric_policy import safe_timeout_result_count
from Virus_Scan.scheduler.timeout.inmemory_timeout_record_value_decisions import (
    timeout_shared_heartbeat_value_decision,
)


def _result_count(value: object, field: str) -> int:
    count, _reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason=field + "_malformed",
        non_finite_reason=field + "_non_finite",
    )
    return count



@dataclass(frozen=True, slots=True)
class InMemoryTimeoutSweepResult:
    evaluated: int
    queued_waits: int
    assigned_waits: int
    hard_timeouts: int
    orphaned_workers: int
    progress_stalls: int
    cancelled_after_stall: int
    shared_heartbeats_observed: int = 0
    shared_heartbeat_cancel_requests: int = 0
    timeout_retry_evidence: tuple[Mapping[str, object], ...] = ()
    timeout_reporting_failures: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evaluated", _result_count(self.evaluated, "evaluated"))
        object.__setattr__(self, "queued_waits", _result_count(self.queued_waits, "queued_waits"))
        object.__setattr__(self, "assigned_waits", _result_count(self.assigned_waits, "assigned_waits"))
        object.__setattr__(self, "hard_timeouts", _result_count(self.hard_timeouts, "hard_timeouts"))
        object.__setattr__(self, "orphaned_workers", _result_count(self.orphaned_workers, "orphaned_workers"))
        object.__setattr__(self, "progress_stalls", _result_count(self.progress_stalls, "progress_stalls"))
        object.__setattr__(self, "cancelled_after_stall", _result_count(self.cancelled_after_stall, "cancelled_after_stall"))
        object.__setattr__(self, "shared_heartbeats_observed", _result_count(self.shared_heartbeats_observed, "shared_heartbeats_observed"))
        object.__setattr__(self, "shared_heartbeat_cancel_requests", _result_count(self.shared_heartbeat_cancel_requests, "shared_heartbeat_cancel_requests"))
        object.__setattr__(self, "timeout_retry_evidence", immutable_tuple(self.timeout_retry_evidence))
        object.__setattr__(self, "timeout_reporting_failures", immutable_tuple(self.timeout_reporting_failures))


def build_inmemory_timeout_sweep_result(
    *,
    evaluated: int,
    queued_waits: int,
    assigned_waits: int,
    hard_timeouts: int,
    orphaned_workers: int,
    progress_stalls: int,
    cancelled_after_stall: int,
    shared_heartbeat_result: object,
    timeout_retry_evidence: tuple[Mapping[str, object], ...],
    timeout_reporting_failures: list[Mapping[str, object]],
) -> InMemoryTimeoutSweepResult:
    """Build the immutable timeout-sweep result at the serialization boundary."""

    return InMemoryTimeoutSweepResult(
        evaluated=evaluated,
        queued_waits=queued_waits,
        assigned_waits=assigned_waits,
        hard_timeouts=hard_timeouts,
        orphaned_workers=orphaned_workers,
        progress_stalls=progress_stalls,
        cancelled_after_stall=cancelled_after_stall,
        shared_heartbeats_observed=safe_timeout_result_count(
            value=timeout_shared_heartbeat_value_decision(
                shared_heartbeat_result, "observed"
            ).as_value(),
            field="shared_heartbeats_observed",
            reporting_failures=timeout_reporting_failures,
        ),
        shared_heartbeat_cancel_requests=safe_timeout_result_count(
            value=timeout_shared_heartbeat_value_decision(
                shared_heartbeat_result, "cancel_requested"
            ).as_value(),
            field="shared_heartbeat_cancel_requests",
            reporting_failures=timeout_reporting_failures,
        ),
        timeout_retry_evidence=tuple(timeout_retry_evidence),
        timeout_reporting_failures=tuple(timeout_reporting_failures),
    )


__all__ = ("InMemoryTimeoutSweepResult", "build_inmemory_timeout_sweep_result")
