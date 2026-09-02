"""Scheduler suppressed-failure telemetry ownership.

This module owns scheduler evidence recording for suppressed queue failures.  It
keeps telemetry failure non-fatal while preserving caller-supplied causal
locations for replay and forensic diagnostics.
"""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.runtime.api import record_scheduler_suppressed, record_suppressed_failure
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS

SUPPRESSION_RECORD_FAILED = False
SUPPRESSION_RECORDED = True


def _process_queue_where(where: object) -> str:
    text, reason = no_hook_text(
        where,
        missing_reason="suppression_where_missing",
        unsupported_reason="process_queue_suppression_where_rejected",
    )
    safe_where = text if reason == "" and text else "suppression_where_rejected"
    return str.__add__("process_queue.", safe_where)

def record_raw_queue_suppressed(where: object, exc: object) -> object:
    """Record a raw-queue suppressed failure without mutating queue state."""
    text, reason = no_hook_text(
        where,
        missing_reason="suppression_where_missing",
        unsupported_reason="raw_queue_suppression_where_rejected",
    )
    safe_where = text if reason == "" and text else "raw_queue_suppression_where_rejected"
    try:
        record_scheduler_suppressed(safe_where, exc)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS:
        return SUPPRESSION_RECORD_FAILED
    return SUPPRESSION_RECORDED


def record_process_queue_suppressed(where: object, exc: object, *, extra: object=None) -> object:
    """Record a process-queue suppressed failure with stable attribution."""
    try:
        context = (
            None
            if extra is None
            else dict.copy(extra)
            if type(extra) is dict
            else {"suppression_extra_rejected": True, "extra_type": no_hook_type_name(extra)}
        )
        record_suppressed_failure(_process_queue_where(where), exc, domain="scheduler", context=context)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS:
        return SUPPRESSION_RECORD_FAILED
    return SUPPRESSION_RECORDED
