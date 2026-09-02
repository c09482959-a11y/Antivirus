"""Canonical detector-failure state owner for Phase C.

Detector failures were previously appended to module-level lists and mirrored
through implicit module state.  This owner provides the single mutable boundary:
callers record, snapshot, and clear through the owner rather than sharing the
live list object across runtime namespaces.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from time import time
from typing import Mapping, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value
from Virus_Scan.runtime.governance_inputs import runtime_bool

if TYPE_CHECKING:
    from types import MappingProxyType

_DETECTOR_SAFE_EXCEPTION_TYPES = (
    AssertionError,
    EOFError,
    FileNotFoundError,
    ImportError,
    LookupError,
    ModuleNotFoundError,
    NameError,
    OSError,
    PermissionError,
    RuntimeError,
    TimeoutError,
    TypeError,
    UnicodeError,
    ValueError,
)


@dataclass(frozen=True)
class _DetectorExceptionArgsProbe:
    args: tuple[object, ...]
    unavailable_reason: str


def _detector_exception_args(exc: BaseException) -> _DetectorExceptionArgsProbe:
    if type(exc) not in _DETECTOR_SAFE_EXCEPTION_TYPES:
        return _DetectorExceptionArgsProbe((), "detector_error_type_rejected")
    try:
        args = BaseException.__getattribute__(exc, "args")
    except (RuntimeError, TypeError, ValueError, UnicodeError):
        return _DetectorExceptionArgsProbe((), "detector_error_args_unavailable")
    if type(args) is tuple:
        return _DetectorExceptionArgsProbe(args, "")
    return _DetectorExceptionArgsProbe((), "detector_error_args_rejected")


def _detector_exception_message(
    exc: BaseException,
) -> tuple[str, str]:
    args_probe = _detector_exception_args(exc)
    if args_probe.unavailable_reason:
        return no_hook_type_name(exc), "detector_error_text_rejected"
    args = args_probe.args
    if len(args) == 0:
        return "", ""
    parts: list[str] = []
    rejected = False
    for item in args[:8]:
        text, reason = no_hook_text(
            item,
            missing_reason="detector_error_missing",
            unsupported_reason="detector_error_text_rejected",
        )
        if reason:
            rejected = True
        parts.append(text if not reason else no_hook_type_name(item))
    return ", ".join(parts)[:500], ("detector_error_text_rejected" if rejected else "")


class DetectorStateOwner:
    def __init__(self) -> None:
        self._lock = RLock()
        self._errors: list[dict[str, object]] = []
        self._strict = False

    def configure(self, *, strict: bool | None = None) -> None:
        if strict is None:
            return
        strict_value, issues = runtime_bool(
            strict,
            field_name="detector_state_strict",
            default=False,
        )
        if issues:
            exception_message = "detector state strict mode rejected"
            raise ValueError(exception_message)
        with self._lock:
            self._strict = strict_value

    def record(self, detector_name: object, exc: BaseException | object, context: Mapping[str, object] | None = None) -> dict[str, object]:
        detector, detector_reason = no_hook_text(
            detector_name,
            missing_reason="detector_name_missing",
            unsupported_reason="detector_name_rejected",
        )
        if isinstance(exc, BaseException):
            error, error_reason = _detector_exception_message(exc)
        else:
            error, error_reason = no_hook_text(
                exc,
                missing_reason="detector_error_missing",
                unsupported_reason="detector_error_text_rejected",
            )
        if detector_reason or detector == "":
            detector = "detector_input_rejected"
        if error_reason or error == "":
            error = no_hook_type_name(exc)
        entry = {
            'detector': detector,
            'error': error,
            'context': freeze_runtime_value({} if context is None else context),
            'time': time(),
        }
        if detector_reason or error_reason:
            entry["input_evidence"] = freeze_runtime_value(
                {
                    "detector_reason": detector_reason,
                    "error_reason": error_reason,
                    "detector_type": no_hook_type_name(detector_name),
                    "error_type": no_hook_type_name(exc),
                }
            )
        with self._lock:
            self._errors.append(entry)
        return entry

    def snapshot(self, *, clear: bool = False) -> tuple[dict[str, object], ...]:
        with self._lock:
            errors = tuple(materialize_runtime_value(item) for item in self._errors)
            if clear:
                self._errors.clear()
        return errors

    def readonly(self) -> MappingProxyType:
        with self._lock:
            return freeze_runtime_value({'errors': tuple(self._errors), 'strict': self._strict})

    def strict(self) -> bool:
        with self._lock:
            return self._strict


_DETECTOR_STATE = DetectorStateOwner()


def record_detector_failure(detector_name: object, exc: BaseException | object, context: Mapping[str, object] | None = None) -> dict[str, object]:
    return _DETECTOR_STATE.record(detector_name, exc, context)


def detector_errors_snapshot(*, clear: bool = False) -> tuple[dict[str, object], ...]:
    return _DETECTOR_STATE.snapshot(clear=clear)


def detector_state_is_strict() -> bool:
    return _DETECTOR_STATE.strict()


__all__ = (
    'DetectorStateOwner',
    'detector_errors_snapshot',
    'detector_state_is_strict',
    'record_detector_failure',
)
