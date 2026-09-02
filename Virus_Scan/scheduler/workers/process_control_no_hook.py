"""No-hook process-control input helpers for scheduler worker termination."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict, no_hook_type_name
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text

if TYPE_CHECKING:
    from collections.abc import Callable

_ALLOWED_PROCESS_METHODS = frozenset(("poll", "terminate", "kill", "is_alive"))
_EXACT_OWNED_COLLECTIONS = (tuple, list, set, frozenset)


def safe_process_control_int(value: object, *, replacement_value: int = 0, minimum: int | None = None, reason: str) -> tuple[int, str]:
    parsed = scheduler_int(value, default=replacement_value, minimum=minimum, reason=reason)
    return parsed


def safe_process_control_text(value: object, *, replacement_text: str, reason: str) -> tuple[str, str]:
    text, failure = scheduler_text(value, replacement_text=replacement_text, unsupported_reason=reason)
    return (text or replacement_text), failure


def safe_process_control_exception_name(exc: object) -> str:
    exception_name = no_hook_type_name(exc)
    return exception_name


def safe_process_pid(proc: object) -> tuple[int, str]:
    if proc is None:
        return 0, "missing_process_handle"
    proc_type = type(proc)
    try:
        if type.__getattribute__(proc_type, "__getattribute__") is not object.__getattribute__:
            return 0, "unsupported_process_handle_getattribute"
    except (AttributeError, TypeError):
        return 0, "unsupported_process_handle_type"
    data = no_hook_plain_instance_dict(proc)
    if data is not None:
        pid_value = dict.get(data, "pid")
        if pid_value is not None:
            pid, reason = scheduler_int(pid_value, default=0, minimum=0, reason="process_handle_pid_rejected")
            return pid, reason
    try:
        mro = type.__getattribute__(proc_type, "__mro__")
    except (AttributeError, TypeError):
        return 0, "unsupported_process_handle_type"
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError):
            return 0, "unsupported_process_handle_class_dict"
        if "pid" not in class_dict:
            continue
        pid_value = class_dict.get("pid")
        if type(pid_value) in {int, str, float}:
            pid, reason = scheduler_int(pid_value, default=0, minimum=0, reason="process_handle_pid_rejected")
            return pid, reason
        return 0, "process_handle_pid_descriptor_rejected"
    return 0, "process_handle_pid_missing"


def _class_callable(proc: object, method_name: str) -> tuple[Callable[..., object] | None, str]:
    if type(method_name) is not str or method_name not in _ALLOWED_PROCESS_METHODS:
        return None, "process_handle_method_rejected"
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


def call_process_method(proc: object, method_name: str) -> tuple[object, str]:
    method, reason = _class_callable(proc, method_name)
    if reason:
        return None, reason
    if method is None:
        return None, "process_handle_method_unavailable"
    try:
        return method(proc), ""
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        reason = safe_process_control_exception_name(exc)
        return None, reason


def owned_job_ids_active(value: object) -> tuple[bool, str]:
    if value is None:
        return False, ""
    if type(value) in _EXACT_OWNED_COLLECTIONS:
        return len(value) > 0, ""
    return True, "owned_job_ids_rejected"


__all__ = (
    "call_process_method",
    "owned_job_ids_active",
    "safe_process_control_exception_name",
    "safe_process_control_int",
    "safe_process_control_text",
    "safe_process_pid",
)
