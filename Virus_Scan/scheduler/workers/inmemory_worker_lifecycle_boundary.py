"""No-hook text and numeric boundary helpers for in-memory worker lifecycle evidence."""
from __future__ import annotations

from typing import cast

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int

_WORKER_LIFECYCLE_UNKNOWN_EXCEPTION_TEXT = "unknown"
_WORKER_THREAD_PROGRESS_JOB_TEXT = "worker"
_WORKER_THREAD_PROGRESS_STAGE_TEXT = "scan"
_WORKER_THREAD_PROGRESS_REASON_TEXT = "shared heartbeat publication failed"
_PARENT_WORKER_MESSAGE_TEXT = "worker_message"
_HEARTBEAT_OPERATION_TEXT = "heartbeat"
_HEARTBEAT_JOB_TEXT = "unknown"
_WORKER_LIFECYCLE_PUBLICATION_TEXT = "worker_lifecycle_publication"
_WORKER_LIFECYCLE_PUBLICATION_FAILED_TEXT = "worker_lifecycle_publication_failed"


def safe_lifecycle_int(value: object) -> int:
    if type(value) is bool:
        return int(value)
    number, _reason = scheduler_int(
        value,
        minimum=0,
        reason="worker_lifecycle_int_rejected",
    )
    return number


def safe_lifecycle_text(
    value: object,
    *,
    replacement_text: str,
    missing_reason: str,
    unsupported_reason: str,
) -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    if reason:
        return replacement_text, reason
    stripped = str.strip(text)
    if not stripped:
        return replacement_text, "blank_scheduler_worker_lifecycle_text"
    return stripped, ""


def safe_lifecycle_exception_message(exc: object) -> str:
    """Return exception text without invoking caller-owned exception hooks."""
    if exc is None:
        return _WORKER_LIFECYCLE_UNKNOWN_EXCEPTION_TEXT
    type_name = no_hook_type_name(exc)
    if not issubclass(type(exc), BaseException):
        return type_name
    return scheduler_exception_text(cast("BaseException", exc), max_length=2000, missing_text=type_name)


def safe_worker_thread_progress_evidence_inputs(
    *,
    job_id: object,
    generation: object,
    stage_name: object,
    reason: object,
    progress_counter: object,
) -> tuple[str, int, str, int, str]:
    job_text, _job_reason = safe_lifecycle_text(
        job_id,
        replacement_text=_WORKER_THREAD_PROGRESS_JOB_TEXT,
        missing_reason="missing_worker_thread_progress_job_id",
        unsupported_reason="unsupported_worker_thread_progress_job_id",
    )
    stage_text, _stage_reason = safe_lifecycle_text(
        stage_name,
        replacement_text=_WORKER_THREAD_PROGRESS_STAGE_TEXT,
        missing_reason="missing_worker_thread_progress_stage",
        unsupported_reason="unsupported_worker_thread_progress_stage",
    )
    reason_text, _reason_failure = safe_lifecycle_text(
        reason,
        replacement_text=_WORKER_THREAD_PROGRESS_REASON_TEXT,
        missing_reason="missing_worker_thread_progress_reason",
        unsupported_reason="unsupported_worker_thread_progress_reason",
    )
    attempt, _attempt_reason = scheduler_int(
        generation,
        minimum=0,
        reason="worker_thread_progress_generation_rejected",
    )
    counter, _progress_reason = scheduler_int(
        progress_counter,
        minimum=0,
        reason="worker_thread_progress_counter_rejected",
    )
    return job_text, attempt, stage_text, counter, reason_text


def safe_worker_message_kind(message: object) -> str:
    """Return a parent-worker message kind without executing caller hooks."""
    if type(message) in {list, tuple} and len(message) > 0:
        first_item = message[0]
    else:
        return "unknown"
    if type(message) in {list, tuple}:
        text, reason = no_hook_text(
            first_item,
            missing_reason="missing_parent_worker_message_kind",
            unsupported_reason="unsupported_parent_worker_message_kind",
        )
        if reason == "" and text:
            return text[:80]
        return reason[:80]
    return "unknown"


def safe_worker_message_preview(message: object) -> str:
    """Return deterministic message preview text without repr/iterating unknown values."""
    if message is None:
        return "none"
    if type(message) is str:
        return str.__str__(message)[:500]
    if type(message) in {bool, int, float}:
        text, reason = no_hook_text(message, unsupported_reason="unsupported_parent_worker_message_preview_scalar")
        return (text if reason == "" else reason)[:500]
    if type(message) is list or type(message) is tuple:
        length = len(message)
        kind = safe_worker_message_kind(message)
        return str.__add__(
            str.__add__(no_hook_type_name(message), "[len="),
            str.__add__(int.__str__(length), str.__add__(", kind=", str.__add__(kind, "]"))),
        )[:500]
    if type(message) is dict:
        return str.__add__("dict[len=", str.__add__(int.__str__(len(message)), "]"))[:500]
    return str.__add__("unsupported_message_type:", no_hook_type_name(message))[:500]


def safe_worker_evidence_label(value: object, *, replacement_text: str) -> str:
    text, reason = safe_lifecycle_text(
        value,
        replacement_text=replacement_text,
        missing_reason="missing_worker_evidence_label",
        unsupported_reason="unsupported_worker_evidence_label",
    )
    return text if reason == "" else replacement_text


def worker_lifecycle_exception_reason(exc: object) -> str:
    """Return a deterministic exception reason without executing caller hooks."""
    return str.__add__(no_hook_type_name(exc), str.__add__(": ", safe_lifecycle_exception_message(exc)[:300]))


def safe_parent_worker_message_identity(message: object) -> tuple[str, str]:
    """Return parent-worker message identity evidence without caller-owned hooks."""
    return safe_worker_message_kind(message), safe_worker_message_preview(message)


def existing_lifecycle_reason(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    return ""


__all__ = (
    "existing_lifecycle_reason",
    "safe_lifecycle_exception_message",
    "safe_lifecycle_int",
    "safe_lifecycle_text",
    "safe_parent_worker_message_identity",
    "safe_worker_evidence_label",
    "safe_worker_message_kind",
    "safe_worker_message_preview",
    "safe_worker_thread_progress_evidence_inputs",
    "worker_lifecycle_exception_reason",
)
