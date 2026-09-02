"""Queue-owned retry callback coercion and failure evidence helpers."""
from __future__ import annotations

from types import BuiltinFunctionType
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_type_name
from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE
from Virus_Scan.scheduler.api.contracts import QueueRetryPolicyError
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.queue.retry_callback_evidence import retry_policy_callback_evidence

RETRY_POLICY_EXCEPTIONS = (OSError, RuntimeError, TypeError, ValueError, QueueRetryPolicyError)
_RETRY_CALLBACK_TYPES = frozenset((BuiltinFunctionType, RUNTIME_NATIVE_FUNCTION_TYPE))
_RETRY_MAX_REPLACEMENT = 0
_NOT_RETRYABLE = False


def retry_policy_callback_supported(callback: object) -> bool:
    return type(callback) in _RETRY_CALLBACK_TYPES


def retry_policy_callback_error(callback: object, callback_name: str) -> QueueRetryPolicyError:
    safe_name = str.__str__(callback_name) if type(callback_name) is str and callback_name else "callback"
    return QueueRetryPolicyError("retry policy callback " + safe_name + " rejected: " + no_hook_type_name(callback))


def record_retry_policy_callback_failure(
    *,
    retry_failures: list[dict[str, object]],
    path: object,
    attempt: int,
    callback_name: str,
    error: BaseException,
) -> object:
    evidence = retry_policy_callback_evidence(
        path=path,
        attempt=attempt,
        callback_name=callback_name,
        error=error,
    )
    retry_failures.append(evidence.as_record())
    return evidence


def safe_retry_max(
    *,
    retry_max: Callable[[object], int],
    prev: object,
    path: object,
    retry_failures: list[dict[str, object]],
) -> int:
    callback_error: BaseException | None = None
    value: object = _RETRY_MAX_REPLACEMENT
    if retry_policy_callback_supported(retry_max):
        try:
            value = retry_max(prev)
        except RETRY_POLICY_EXCEPTIONS as exc:
            callback_error = exc
    else:
        callback_error = retry_policy_callback_error(retry_max, "retry_max")
    if callback_error is not None:
        record_retry_policy_callback_failure(
            retry_failures=retry_failures,
            path=path,
            attempt=0,
            callback_name="retry_max",
            error=callback_error,
        )
        value = _RETRY_MAX_REPLACEMENT
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        reason="retry_max_return_rejected",
        non_finite_reason="retry_max_return_non_finite",
    )
    if reason:
        record_retry_policy_callback_failure(
            retry_failures=retry_failures,
            path=path,
            attempt=0,
            callback_name="retry_max",
            error=ValueError(reason),
        )
        return _RETRY_MAX_REPLACEMENT
    return parsed


def safe_is_retryable_failure(
    *,
    is_retryable_failure: Callable[[object], bool],
    value: object,
    path: object,
    attempt: int,
    retry_failures: list[dict[str, object]],
) -> bool:
    callback_error: BaseException | None = None
    callback_result: object = _NOT_RETRYABLE
    if retry_policy_callback_supported(is_retryable_failure):
        try:
            callback_result = is_retryable_failure(value)
        except RETRY_POLICY_EXCEPTIONS as exc:
            callback_error = exc
    else:
        callback_error = retry_policy_callback_error(is_retryable_failure, "is_retryable_failure")
    if callback_error is not None:
        record_retry_policy_callback_failure(
            retry_failures=retry_failures,
            path=path,
            attempt=attempt,
            callback_name="is_retryable_failure",
            error=callback_error,
        )
        callback_result = _NOT_RETRYABLE
    parsed, reason = scheduler_bool(
        callback_result,
        default=False,
        reason="is_retryable_failure_return_rejected",
    )
    if reason:
        record_retry_policy_callback_failure(
            retry_failures=retry_failures,
            path=path,
            attempt=attempt,
            callback_name="is_retryable_failure",
            error=ValueError(reason),
        )
        return _NOT_RETRYABLE
    return parsed


__all__ = (
    "RETRY_POLICY_EXCEPTIONS",
    "record_retry_policy_callback_failure",
    "retry_policy_callback_error",
    "retry_policy_callback_supported",
    "safe_is_retryable_failure",
    "safe_retry_max",
)
