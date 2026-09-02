"""Typed start-wait decisions and record snapshots for in-memory timeout sweeps."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Literal, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import record_timeout_recovery_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_history_contract import (
    TimeoutHistoryTransitionProvider as TimeoutRecoveryBoundary,
)

StartWaitState = Literal[
    "not_armed_backlog_available",
    "not_armed_backlog_full",
    "within_budget",
    "missing_start_time",
    "transitioned_to_wait",
    "transition_failed_recorded",
]
RecordFieldState = Literal["present", "missing", "unsupported_record"]


@dataclass(frozen=True, slots=True)
class StartWaitDecision:
    """Replayable queued/assigned start-wait decision instead of bare 0/1 sentinels."""

    wait_delta: int
    state: StartWaitState
    reason: str


@dataclass(frozen=True, slots=True)
class StartWaitRecoveryFailureRequest:
    failures: list[Mapping[str, object]]
    job_id: object
    record: Mapping[str, object]
    reason: str
    pid: object | None
    action: str
    error: BaseException
    source: str
    record_scheduler_suppressed: Callable[[str, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True, slots=True)
class TimeoutRecordField:
    """No-hook snapshot of a scheduler record field lookup."""

    value: object | None
    state: RecordFieldState
    field: str
    record_type: str


def start_wait_decision(*, wait_delta: int, state: StartWaitState, reason: str) -> StartWaitDecision:
    """Build the typed decision projected to counters by the sweep orchestrator."""

    return StartWaitDecision(wait_delta=wait_delta, state=state, reason=reason)


def timeout_record_field(rec: Mapping[str, object], field: str) -> TimeoutRecordField:
    """Read exact-dict record fields without invoking mapping hooks or hiding absence."""

    if type(rec) is dict and dict.__contains__(rec, field):
        return TimeoutRecordField(
            value=dict.__getitem__(rec, field),
            state="present",
            field=field,
            record_type="dict",
        )
    state: RecordFieldState = "missing" if type(rec) is dict else "unsupported_record"
    return TimeoutRecordField(
        value=None,
        state=state,
        field=field,
        record_type=no_hook_type_name(rec),
    )


def timeout_record_budget_snapshot(rec: Mapping[str, object]) -> Mapping[str, object]:
    """Return typed timeout-budget evidence instead of an empty mapping default."""

    budget = timeout_record_field(rec, "timeout_budget")
    if type(budget.value) is dict:
        return materialize_scheduler_mapping(budget.value)
    return MappingProxyType(
        {
            "state": "timeout_budget_unavailable",
            "reason": budget.state,
            "field": budget.field,
            "record_type": budget.record_type,
            "replay_must_reproduce": True,
        }
    )


def record_start_wait_recovery_failure(request: StartWaitRecoveryFailureRequest) -> None:
    """Record start-wait recovery failure with typed field and budget snapshots."""

    record_timeout_recovery_failure(
        failures=request.failures,
        job_id=request.job_id,
        reason=request.reason,
        pid=request.pid,
        action=request.action,
        attempt=timeout_record_field(request.record, "attempt").value,
        timeout_budget=timeout_record_budget_snapshot(request.record),
        error=request.error,
        source=request.source,
        record_scheduler_suppressed=request.record_scheduler_suppressed,
        recoverable_exceptions=request.recoverable_exceptions,
    )


__all__ = (
    "StartWaitDecision",
    "StartWaitRecoveryFailureRequest",
    "TimeoutRecoveryBoundary",
    "record_start_wait_recovery_failure",
    "start_wait_decision",
    "timeout_record_budget_snapshot",
    "timeout_record_field",
)
