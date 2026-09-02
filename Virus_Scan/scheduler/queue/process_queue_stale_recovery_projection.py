"""No-hook projection helpers for process-queue stale recovery evidence."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.process_queue_stale_recovery_decisions import (
    stale_optional_float_decision,
    stale_recovered_record_decision,
)


def stale_optional_float(value: object) -> float | None:
    return stale_optional_float_decision(value).as_optional_float()


def stale_bool(value: object) -> bool:
    if type(value) is bool:
        return value
    return True


def stale_recovered_record(value: object) -> dict[str, object]:
    return stale_recovered_record_decision(value).as_record()


__all__ = (
    "stale_bool",
    "stale_optional_float",
    "stale_recovered_record",
)
