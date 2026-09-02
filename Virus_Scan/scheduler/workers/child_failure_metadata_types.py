"""Typed child-worker failure metadata boundary contracts."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import NamedTuple, TypeAlias

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value

ChildFailureInfo: TypeAlias = dict[str, object]
ChildFailureJob: TypeAlias = Mapping[str, object] | None
ChildFailureResult: TypeAlias = dict[str, object]
ChildErrorResultBuilder: TypeAlias = Callable[[object, BaseException], object]
ChildFailureReporter: TypeAlias = Callable[[str, BaseException], object]
ChildExceptionInfoBuilder: TypeAlias = Callable[..., ChildFailureInfo]


class ChildAttemptDecision(NamedTuple):
    """Replayable child-job attempt materialization decision."""

    value: int
    available: bool
    reason: str


class ChildResultSnapshotDecision(NamedTuple):
    """Replayable child-worker result snapshot materialization decision."""

    snapshot: ChildFailureResult
    available: bool
    reason: str


def child_failure_int(value: object, *, default: int = 0) -> int:
    if type(value) is bool:
        return int(value)
    if type(value) is int:
        return value
    return default


def child_attempt_decision(job: object) -> ChildAttemptDecision:
    items = no_hook_mapping_items(job)
    if items is None:
        return ChildAttemptDecision(0, False, "child_failure_job_attempt_mapping_unavailable")
    missing = object()
    value = scheduler_mapping_item_value(items, "attempt", missing)
    if value is missing:
        return ChildAttemptDecision(0, False, "child_failure_job_attempt_missing")
    return ChildAttemptDecision(child_failure_int(value, default=0), True, "child_failure_job_attempt_available")


def merge_child_attempt_decision(info: ChildFailureInfo, decision: ChildAttemptDecision) -> ChildFailureInfo:
    info["attempt"] = decision.value
    if not decision.available:
        info["attempt_unavailable_reason"] = decision.reason
    return info

_child_failure_int = child_failure_int
