"""Binary scanner runtime evidence helpers.

These helpers own binary scanner evidence-cache publication and structured
exception metadata. They do not mutate hidden scanner state or invoke
caller-owned exception/string/numeric hooks at evidence boundaries.
"""

from __future__ import annotations

import os
import time

from Virus_Scan.scanners.binary_scan_cache import remember_scan_evidence as _publish_scan_evidence

_BUILTIN_EXCEPTIONS = (
    ArithmeticError,
    AssertionError,
    AttributeError,
    EOFError,
    EnvironmentError,
    Exception,
    ImportError,
    IndexError,
    KeyError,
    LookupError,
    MemoryError,
    NameError,
    NotImplementedError,
    OSError,
    OverflowError,
    RuntimeError,
    SyntaxError,
    TypeError,
    ValueError,
)


def _remember_scan_evidence(path: object, **items: object) -> object:
    """Publish immutable scan evidence handoff records instead of mutating hidden state."""
    return _publish_scan_evidence(path, **items)


def _runtime_evidence_field_reason(field: str, suffix: str) -> str:
    field_text = str.__str__(field) if type(field) is str and field else "field"
    return field_text + suffix


def _exact_text(value: object, *, default: str, field: str) -> tuple[str, str | None]:
    if type(value) is str:
        return value, None
    if value is None:
        return default, _runtime_evidence_field_reason(field, "_missing")
    return default, _runtime_evidence_field_reason(field, "_rejected")


def _exact_int(value: object, *, default: int, field: str) -> tuple[int, str | None]:
    if type(value) is int:
        return value, None
    if value is None:
        return default, _runtime_evidence_field_reason(field, "_missing")
    return default, _runtime_evidence_field_reason(field, "_rejected")


def _builtin_exception_message(exc: BaseException | None) -> tuple[str, str | None]:
    if exc is None:
        return "unknown", "exception_missing"
    if type(exc) in _BUILTIN_EXCEPTIONS:
        args = exc.args
        if args and all(type(arg) is str for arg in args):
            return " ".join(args)[:2000], None
        if not args:
            return type(exc).__name__, "exception_message_empty"
        return type(exc).__name__, "exception_args_non_text"
    return type(exc).__name__, "unsupported_exception_object_rejected"


def _traceback_tail(exc: BaseException | None) -> tuple[str, str | None]:
    if exc is None:
        return "<traceback_unavailable>", "exception_missing"
    if type(exc) not in _BUILTIN_EXCEPTIONS:
        return "<traceback_unavailable>", "unsupported_exception_traceback_rejected"
    # Avoid traceback.format_exception because it stringifies exception objects.
    if exc.__traceback__ is None:
        return "<traceback_unavailable>", "traceback_missing"
    return "<traceback_available_without_stringification>", None


def _safe_exception_info(exc: BaseException | None, *, stage: object = "unknown", worker_pid: object = None, attempt: object = None) -> dict[str, object]:
    stage_text, stage_reason = _exact_text(stage, default="unknown", field="stage")
    pid_default = os.getpid()
    pid, pid_reason = _exact_int(worker_pid, default=pid_default, field="worker_pid")
    error_text, error_reason = _builtin_exception_message(exc)
    traceback_tail, traceback_reason = _traceback_tail(exc)
    info: dict[str, object] = {
        "stage": stage_text or "unknown",
        "exception_type": type(exc).__name__ if exc is not None else "unknown",
        "error": error_text,
        "traceback_tail": traceback_tail,
        "worker_pid": pid,
        "attempt": attempt if type(attempt) in {int, str} or attempt is None else None,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if stage_reason is not None:
        info["stage_unavailable_reason"] = stage_reason
    if pid_reason is not None:
        info["worker_pid_unavailable_reason"] = pid_reason
    if error_reason is not None:
        info["error_unavailable_reason"] = error_reason
    if traceback_reason is not None:
        info["traceback_unavailable_reason"] = traceback_reason
    if attempt is not None and type(attempt) not in {int, str}:
        info["attempt_unavailable_reason"] = "attempt_rejected"
    return info


__all__ = ("_remember_scan_evidence", "_safe_exception_info")
