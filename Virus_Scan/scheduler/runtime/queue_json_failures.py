"""Explicit queue failure diagnostic records for scheduler JSON persistence."""
from __future__ import annotations

from Virus_Scan.scheduler.runtime.queue_json_failure_info import (
    _queue_failure_extra as _queue_failure_extra_impl,
    queue_default_failure_info,
)
from Virus_Scan.scheduler.runtime.queue_json_failure_recording import (
    QUEUE_FAILURE_NOT_RECORDED,
    QUEUE_FAILURE_RECORDED,
    record_process_queue_failure,
)


def _queue_failure_extra(extra: object) -> tuple[tuple[str, object], ...]:
    if extra is None:
        return ()
    return _queue_failure_extra_impl(extra)


_queue_default_failure_info = queue_default_failure_info
_record_process_queue_failure = record_process_queue_failure

__all__ = (
    "QUEUE_FAILURE_NOT_RECORDED",
    "QUEUE_FAILURE_RECORDED",
    "_queue_default_failure_info",
    "_queue_failure_extra",
    "_record_process_queue_failure",
    "queue_default_failure_info",
    "record_process_queue_failure",
)
