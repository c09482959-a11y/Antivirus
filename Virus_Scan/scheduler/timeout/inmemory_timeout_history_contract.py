"""Request-based timeout recovery history transition boundary."""
from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
import operator
from typing import Protocol, cast


class TimeoutHistoryTransitionProvider(Protocol):
    """Structural owner exposing the existing transition callable as data."""

    replace_with_history_transition: object


@dataclass(frozen=True, slots=True)
class TimeoutHistoryTransitionRequest:
    """Complete immutable input for one timeout history transition."""

    job_id: object
    record: Mapping[str, object]
    reason: str
    pid: object | None = None
    now: float | None = None
    action: str = "history"
    extra: Mapping[str, object] | None = None


def replace_timeout_history_transition(
    recovery: TimeoutHistoryTransitionProvider,
    request: TimeoutHistoryTransitionRequest,
) -> MutableMapping[str, object]:
    """Invoke the tested recovery method through one request-based owner."""

    result = operator.call(
        recovery.replace_with_history_transition,
        request.job_id,
        request.record,
        request.reason,
        pid=request.pid,
        now=request.now,
        action=request.action,
        extra=request.extra,
    )
    return cast("MutableMapping[str, object]", result)


__all__ = (
    "TimeoutHistoryTransitionProvider",
    "TimeoutHistoryTransitionRequest",
    "replace_timeout_history_transition",
)
