"""No-hook support for scheduler partial-output evidence publication."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_finite_float
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text

if TYPE_CHECKING:
    from collections.abc import Callable


def emit_partial_output_log(log_error: Callable[[str], object], message: str) -> bool:
    """Emit an internal partial-output log line without allowing logging failure to escape."""
    emitted = False
    if type(message) is not str:
        message = "scheduler_partial_output: internal log message rejected without caller hooks"
    try:
        log_error(str.__str__(message))
        emitted = True
    except (OSError, RuntimeError, TypeError, ValueError):
        emitted = False
    return emitted


def _partial_context_text(context: str) -> str:
    if type(context) is str and context:
        return str.__str__(context)
    return "scheduler_partial_output"



def _partial_rejection_message(context_text: str, field: str, reason: str) -> str:
    return str.__add__(str.__add__(str.__add__(str.__add__(context_text, ": "), field), " rejected without caller hooks: "), reason)


def _emit_rejection(log_error: Callable[[str], object], context: str, field: str, reason: str) -> None:
    emit_partial_output_log(log_error, _partial_rejection_message(_partial_context_text(context), field, reason))


def partial_output_target(value: object, *, context: str, log_error: Callable[[str], object]) -> tuple[str, str]:
    """Return a safe partial-output target suffix path and rejection reason."""
    target, reason = scheduler_path_text(value)
    if reason:
        if reason == "scheduler_path_missing":
            return "", reason
        _emit_rejection(log_error, context, "partial_output_path", reason)
        return "", reason
    if target == "":
        return "", "scheduler_path_blank"
    return str.__add__(str.__str__(target), ".partial"), ""


def partial_result_count(results: object, *, context: str, log_error: Callable[[str], object]) -> int | None:
    """Count exact owned result containers without invoking external ``__len__``."""
    if type(results) in {dict, list, tuple}:
        return len(results)
    _emit_rejection(log_error, context, "results", "unsupported_partial_results_container")
    return None


def partial_every_value(value: object, *, context: str, log_error: Callable[[str], object]) -> int:
    if value is None:
        return 0
    every, reason = no_hook_exact_nonnegative_int(value, default=0, reason="unsafe_partial_output_every", allow_exact_text=True)
    if reason:
        _emit_rejection(log_error, context, "partial_output_every", reason)
    return every


def partial_total_files_value(value: object, *, context: str, log_error: Callable[[str], object]) -> int:
    if value is None:
        return 0
    total, reason = no_hook_exact_nonnegative_int(value, default=0, reason="unsafe_partial_total_files", allow_exact_text=True)
    if reason:
        _emit_rejection(log_error, context, "total_files", reason)
    return total


def partial_timestamp_value(value: object, *, context: str, field: str, log_error: Callable[[str], object]) -> float:
    if value is None:
        return 0.0
    metric, reason = no_hook_finite_float(value, default=0.0, minimum=0.0, reason=str.__add__("unsafe_", field))
    if reason:
        _emit_rejection(log_error, context, field, reason)
    return metric


def partial_force_value(value: object, *, context: str, log_error: Callable[[str], object]) -> bool:
    if type(value) is bool:
        return value
    if value is None:
        return False
    _emit_rejection(log_error, context, "force", "unsafe_partial_force_boolean")
    return False


def partial_due_by_count(result_count: int, every: int) -> bool:
    return result_count == 1 or result_count % max(1, every) == 0


__all__ = (
    "emit_partial_output_log",
    "partial_due_by_count",
    "partial_every_value",
    "partial_force_value",
    "partial_output_target",
    "partial_result_count",
    "partial_timestamp_value",
    "partial_total_files_value",
)
