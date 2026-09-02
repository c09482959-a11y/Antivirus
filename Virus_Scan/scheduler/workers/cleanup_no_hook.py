"""No-hook process cleanup boundary helpers."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.scheduler.workers.process_control_no_hook import (
    safe_process_control_exception_name,
    safe_process_control_int,
    safe_process_control_text,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_ALLOWED_CLEANUP_METHODS = frozenset(("wait", "poll", "terminate", "kill"))


def cleanup_method(proc: object, method_name: str) -> tuple[Callable[..., object] | None, str]:
    if type(method_name) is not str or method_name not in _ALLOWED_CLEANUP_METHODS:
        return None, "worker_cleanup_method_rejected"
    if proc is None:
        return None, "missing_process_handle"
    proc_type = type(proc)
    try:
        if type.__getattribute__(proc_type, "__getattribute__") is not object.__getattribute__:
            return None, "unsupported_process_handle_getattribute"
        mro = type.__getattribute__(proc_type, "__mro__")
    except (AttributeError, TypeError):
        return None, "unsupported_process_handle_type"
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError):
            return None, "unsupported_process_handle_class_dict"
        if method_name not in class_dict:
            continue
        method = class_dict.get(method_name)
        if callable(method):
            return method, ""
        return None, "process_handle_method_descriptor_rejected"
    return None, "process_handle_method_missing"


def call_cleanup_method(proc: object, method_name: str, **kwargs: object) -> tuple[object, str]:
    method, reason = cleanup_method(proc, method_name)
    if reason:
        return None, reason
    if method is None:
        return None, "worker_cleanup_method_unavailable"
    try:
        return method(proc, **kwargs), ""
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        reason = safe_process_control_exception_name(exc)
        return None, reason


def cleanup_output_text(output: object) -> str:
    text, reason = scheduler_path_text(output)
    if reason == "" and text:
        return text
    text_value, text_reason = safe_process_control_text(
        output,
        replacement_text="worker_output_rejected",
        reason="worker_cleanup_output_rejected",
    )
    if text_reason == "" and text_value:
        return text_value
    return "worker_output_rejected"


def cleanup_timeout(value: object) -> float:
    timeout, _reason = safe_process_control_int(
        value,
        replacement_value=0,
        minimum=0,
        reason="worker_cleanup_timeout_rejected",
    )
    if timeout > 0:
        return float(timeout)
    if type(value) is float and value >= 0.0:
        return value
    return 0.0


__all__ = (
    "call_cleanup_method",
    "cleanup_method",
    "cleanup_output_text",
    "cleanup_timeout",
)
