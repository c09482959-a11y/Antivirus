"""Queue-owned process-queue issue reporting bindings."""
from __future__ import annotations



from Virus_Scan.runtime.api import record_scheduler_suppressed
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.evidence.raw_queue_issue import record_raw_queue_issue as _record_raw_queue_issue_impl
from Virus_Scan.scheduler.evidence.suppressed_failures import (
    record_process_queue_suppressed as _stage113_record_process_queue_suppressed,
    record_raw_queue_suppressed as _raw_record_scheduler_suppressed,
)


def record_raw_queue_issue(
    stage: str,
    exc: BaseException,
    *,
    fatal: bool = False,
    extra: dict[str, object] | None = None,
) -> object:
    return _record_raw_queue_issue_impl(
        stage,
        exc,
        fatal=fatal,
        extra=extra,
        record_scheduler_suppressed=record_scheduler_suppressed,
        record_raw_suppressed=_raw_record_scheduler_suppressed,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )

record_process_queue_suppressed = _stage113_record_process_queue_suppressed

__all__ = ("record_process_queue_suppressed", "record_raw_queue_issue")
