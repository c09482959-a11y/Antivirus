"""Typed no-hook numeric outcomes for scheduler worker IPC lifecycle."""
from __future__ import annotations

from dataclasses import dataclass
import math


from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS


@dataclass(frozen=True, slots=True)
class WorkerLifecycleIntOutcome:
    value: int
    reason: str
    replacement_used: bool


@dataclass(frozen=True, slots=True)
class WorkerLifecycleFloatOutcome:
    value: float
    reason: str
    replacement_used: bool



def _rejected_int(replacement: int, reason: str) -> WorkerLifecycleIntOutcome:
    fallback = 0
    if type(replacement) is int and type(replacement) is not bool and replacement >= 0:
        fallback = replacement
    return WorkerLifecycleIntOutcome(fallback, reason, replacement_used=True)


def _rejected_float(replacement: float, reason: str) -> WorkerLifecycleFloatOutcome:
    fallback = 0.0
    metric = fallback
    if type(replacement) is int and type(replacement) is not bool:
        metric = replacement + 0.0
    elif type(replacement) is float:
        metric = replacement
    if math.isfinite(metric) and metric >= 0.0:
        fallback = metric
    return WorkerLifecycleFloatOutcome(fallback, reason, replacement_used=True)


def _accepted_int(value: int) -> WorkerLifecycleIntOutcome:
    if value >= 0:
        return WorkerLifecycleIntOutcome(value, "", replacement_used=False)
    return WorkerLifecycleIntOutcome(0, "negative_worker_lifecycle_int", replacement_used=True)


def _accepted_float(value: float) -> WorkerLifecycleFloatOutcome:
    if value >= 0.0:
        return WorkerLifecycleFloatOutcome(value, "", replacement_used=False)
    return WorkerLifecycleFloatOutcome(0.0, "negative_worker_lifecycle_float", replacement_used=True)


def _exact_int_text(text: str, replacement: int) -> WorkerLifecycleIntOutcome:
    stripped = str.__str__(text).strip()
    if not stripped:
        return _rejected_int(replacement, "blank_worker_lifecycle_int")
    sign = 1
    digits = stripped
    if stripped[0] in {"+", "-"}:
        if len(stripped) == 1:
            return _rejected_int(replacement, "sign_only_worker_lifecycle_int")
        sign = -1 if stripped[0] == "-" else 1
        digits = stripped[1:]
    if not digits.isdecimal():
        return _rejected_int(replacement, "non_decimal_worker_lifecycle_int")
    return _accepted_int(sign * int(digits, 10))


def worker_lifecycle_int_outcome(value: object, replacement: int = 0) -> WorkerLifecycleIntOutcome:
    if type(value) is bool:
        return _rejected_int(replacement, "bool_worker_lifecycle_int")
    if type(value) is int:
        return _accepted_int(value)
    if type(value) is float:
        if math.isfinite(value) and value.is_integer():
            return _accepted_int(int(value))
        return _rejected_int(replacement, "non_integral_worker_lifecycle_int")
    if type(value) is str:
        return _exact_int_text(value, replacement)
    if type(value) is bytes:
        return _exact_int_text(bytes(value).decode("utf-8", "replace"), replacement)
    if type(value) is bytearray:
        return _exact_int_text(bytes(value).decode("utf-8", "replace"), replacement)
    return _rejected_int(replacement, "unsupported_worker_lifecycle_int")


def worker_lifecycle_int(value: object, replacement: int = 0) -> int:
    return worker_lifecycle_int_outcome(value, replacement).value


def _float_from_text(text: str, replacement: float) -> WorkerLifecycleFloatOutcome:
    stripped = str.__str__(text).strip()
    if not stripped:
        return _rejected_float(replacement, "blank_worker_lifecycle_float")
    try:
        metric = float(stripped)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _rejected_float(replacement, "invalid_worker_lifecycle_float")
    if not math.isfinite(metric):
        return _rejected_float(replacement, "non_finite_worker_lifecycle_float")
    return _accepted_float(metric)


def worker_lifecycle_float_outcome(value: object, replacement: float = 0.0) -> WorkerLifecycleFloatOutcome:
    if type(value) is bool:
        return _rejected_float(replacement, "bool_worker_lifecycle_float")
    if type(value) is int:
        return _accepted_float(value + 0.0)
    if type(value) is float:
        if math.isfinite(value):
            return _accepted_float(value)
        return _rejected_float(replacement, "non_finite_worker_lifecycle_float")
    if type(value) is str:
        return _float_from_text(value, replacement)
    if type(value) is bytes:
        return _float_from_text(bytes(value).decode("utf-8", "replace"), replacement)
    if type(value) is bytearray:
        return _float_from_text(bytes(value).decode("utf-8", "replace"), replacement)
    return _rejected_float(replacement, "unsupported_worker_lifecycle_float")


def worker_lifecycle_float(value: object, replacement: float = 0.0) -> float:
    return worker_lifecycle_float_outcome(value, replacement).value


__all__ = (
    "WorkerLifecycleFloatOutcome",
    "WorkerLifecycleIntOutcome",
    "worker_lifecycle_float",
    "worker_lifecycle_float_outcome",
    "worker_lifecycle_int",
    "worker_lifecycle_int_outcome",
)
