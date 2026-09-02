"""Queue-terminal accounting evidence and message helpers."""
from __future__ import annotations

from types import BuiltinFunctionType
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text

_REPORT_CALLBACK_TYPES = frozenset((BuiltinFunctionType, RUNTIME_NATIVE_FUNCTION_TYPE))
_REPORT_FAILURE_MARKER = "queue_terminal_accounting_failed"
_REPORT_MARKER_REJECTED = "queue_terminal_report_marker_rejected"
_REPORT_EXTRA_REJECTED = "queue_terminal_report_extra_rejected"
_TERMINAL_REASON_PREFIX = "queue_terminal_"
_TERMINAL_REASON_SUFFIX = "_rejected"
_UNSUPPORTED_FILE_PREFIX = "unsupported_queue_file_"
_TERMINAL_REPORT_EXCEPTIONS = (OSError, RuntimeError, TypeError, ValueError)
_TERMINAL_REPORT_FAILED = bool(0)



def terminal_callback_supported(callback: object) -> bool:
    return type(callback) in _REPORT_CALLBACK_TYPES


def terminal_marker(*parts: str) -> str:
    safe_parts: list[str] = []
    for part in parts:
        if type(part) is str and part:
            safe_parts.append(str.__str__(part))
        else:
            safe_parts.append("unsupported_terminal_marker_part")
    return str.join("_", safe_parts)


def terminal_rejection_reason(field_name: str) -> str:
    if type(field_name) is str and field_name:
        return _TERMINAL_REASON_PREFIX + str.__str__(field_name) + _TERMINAL_REASON_SUFFIX
    return "queue_terminal_field_rejected"


def terminal_unsupported_file_key(index: object) -> str:
    safe_index, _reason = no_hook_exact_nonnegative_int(
        index,
        reason="queue_file_index_rejected",
        non_finite_reason="queue_file_index_non_finite",
    )
    return _UNSUPPORTED_FILE_PREFIX + int.__str__(safe_index)


def terminal_waiting_message(workers: int) -> str:
    return (
        "bulk scan queue drained; waiting for "
        + int.__str__(workers)
        + " worker process(es) to exit/write final output"
    )


def terminal_terminating_message(workers: int, grace: float) -> str:
    return (
        "bulk scan queue drained; terminating "
        + int.__str__(workers)
        + " idle worker process(es) after grace="
        + float.__format__(grace, ".1f")
        + "s"
    )


def terminal_missing_results_message(missing_count: int) -> str:
    return (
        "bulk scan queue drained with missing file accounting; "
        "synthesized_failed_results="
        + int.__str__(missing_count)
        + " and terminating idle workers"
    )


def report_terminal_accounting_failure(
    report: Callable[..., object] | None,
    marker: str,
    exc: BaseException,
    *,
    extra: dict[str, object] | None = None,
) -> bool:
    if report is None or not terminal_callback_supported(report):
        return False
    safe_marker, marker_reason = scheduler_text(
        marker,
        replacement_text=_REPORT_FAILURE_MARKER,
        unsupported_reason=_REPORT_MARKER_REJECTED,
    )
    safe_extra = materialize_scheduler_mapping({} if extra is None else extra)
    if type(safe_extra) is not dict:
        safe_extra = {
            "queue_terminal_accounting_extra_rejected": True,
            "reason": _REPORT_EXTRA_REJECTED,
        }
    if marker_reason:
        safe_extra["marker_reason"] = marker_reason
    try:
        report(safe_marker, exc, fatal=False, extra=safe_extra)
    except _TERMINAL_REPORT_EXCEPTIONS as report_exc:
        try:
            record_suppressed_failure(
                "queue_terminal_accounting_report_callback_failed",
                report_exc,
                domain="scheduler",
                context={
                    "queue_terminal_accounting_failed": True,
                    "queue_terminal_accounting_report_callback_failed": True,
                    "marker": safe_marker,
                    "extra": materialize_scheduler_mapping(safe_extra),
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_record": True,
                },
            )
        except _TERMINAL_REPORT_EXCEPTIONS:
            return _TERMINAL_REPORT_FAILED
        return _TERMINAL_REPORT_FAILED
    return True


__all__ = (
    "report_terminal_accounting_failure",
    "terminal_marker",
    "terminal_missing_results_message",
    "terminal_rejection_reason",
    "terminal_terminating_message",
    "terminal_unsupported_file_key",
    "terminal_waiting_message",
)
