"""No-hook scalar support for global raw queue execution."""
from __future__ import annotations

import math


from Virus_Scan.scheduler.execution.queue_scan_outcome import GlobalRawQueueScanOutcome, raw_queue_scan_failed

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path, scheduler_exception_text


class GlobalRawQueueTimeoutError(TimeoutError):
    """Scheduler-owned timeout detail with primitive-only args."""


def exact_stage_text(value: object) -> tuple[str, str]:
    text, reason = no_hook_text(value, missing_reason="raw_queue_effective_stage_missing", unsupported_reason="raw_queue_effective_stage_rejected")
    if reason == "" and text:
        return text, ""
    return "", reason


def router_stage_tag(stage: str) -> str:
    if type(stage) is str:
        return str.__add__("router_stage_", str.__str__(stage))
    return "router_stage_unavailable"



def exact_timeout_seconds(timeout_sec: object, *, job_count: int) -> tuple[float, str]:
    default_value = max(120.0, job_count * 2.0)
    if timeout_sec is None or timeout_sec == 0:
        return default_value, ""
    if type(timeout_sec) is bool:
        return default_value, "raw_queue_timeout_rejected"
    if type(timeout_sec) in {int, float}:
        value = float(timeout_sec)
        if math.isfinite(value) and value > 0.0:
            return value, ""
    if type(timeout_sec) is str:
        try:
            value = float(str.__str__(timeout_sec).strip())
        except (TypeError, ValueError, OverflowError):
            return default_value, "raw_queue_timeout_rejected"
        if math.isfinite(value) and value > 0.0:
            return value, ""
    return default_value, "raw_queue_timeout_rejected"


def queue_timeout_message(path: object, accum: object) -> str:
    completed = "unknown"
    expected = "unknown"
    if type(accum) is dict:
        raw_completed = dict.get(accum, "completed")
        raw_expected = dict.get(accum, "expected")
        if type(raw_completed) is str:
            completed = str.__str__(raw_completed)
        elif type(raw_completed) is int:
            completed = int.__str__(raw_completed)
        if type(raw_expected) is str:
            expected = str.__str__(raw_expected)
        elif type(raw_expected) is int:
            expected = int.__str__(raw_expected)
    path_text = scheduler_evidence_path(path, field_name="raw_queue_path")
    return "global raw queue timeout for " + path_text + ": completed=" + completed + " expected=" + expected


def queue_failure_log_message(path: object, exc: BaseException) -> str:
    return (
        "global raw queue scan failed for "
        + scheduler_evidence_path(path, field_name="raw_queue_path")
        + ": "
        + scheduler_exception_text(exc)
        + "; raw scan marked incomplete"
    )


def record_queue_failure_outcome(deps: object, path: object, exc: BaseException) -> GlobalRawQueueScanOutcome:
    try:
        deps.log_error(queue_failure_log_message(path, exc))
    except (OSError, UnicodeError, RuntimeError) as log_exc:
        deps.record_issue("global_raw_scan.log_failed", log_exc)
    deps.record_degradation(path, exc, where="global_raw_scan_file_via_queue")
    return raw_queue_scan_failed("global_raw_scan_file_via_queue_failed", exc)


__all__ = (
    "GlobalRawQueueTimeoutError",
    "exact_stage_text",
    "exact_timeout_seconds",
    "queue_timeout_message",
    "record_queue_failure_outcome",
    "router_stage_tag",
)
