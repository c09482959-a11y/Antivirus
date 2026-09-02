"""Shared raw queue identity issue reporting helpers."""
from __future__ import annotations

from collections.abc import Callable

from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS


def record_identity_helper_issue(
    where: object,
    exc: object,
    *,
    default_marker: str = "raw_queue_identity",
    recorder: Callable[[object, object], object] | None = None,
) -> bool:
    """Record raw queue identity helper issues without invoking caller hooks."""
    marker = where if type(where) is str and where != "" else default_marker
    suppressed = False
    reporter = record_scheduler_suppressed if recorder is None else recorder
    try:
        reporter(marker, exc)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS:
        suppressed = True
    return suppressed


__all__ = ("record_identity_helper_issue",)
