"""Canonical exact scheduler status predicate helpers."""
from __future__ import annotations


def scheduler_status_equals(status: object, expected: str) -> bool:
    """Return whether an owned scheduler status exactly matches expected text."""
    return type(status) is str and str.__eq__(status, expected)


def scheduler_status_not(status: object, rejected: str) -> bool:
    """Return whether an owned scheduler status is not the rejected text."""
    return not scheduler_status_equals(status, rejected)


def scheduler_reason_empty(reason: object) -> bool:
    """Return whether a replayable scheduler reason field represents success."""
    return scheduler_status_equals(reason, "")


__all__ = (
    "scheduler_reason_empty",
    "scheduler_status_equals",
    "scheduler_status_not",
)
