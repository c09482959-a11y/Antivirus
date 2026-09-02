"""Bounded retry-policy execution steps for raw queue files."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.queue.retry_integrity_access import safe_result_scan_integrity as _read_result_integrity
from Virus_Scan.scheduler.queue.retry_integrity_persistence import record_retry_integrity_persistence_failure
from Virus_Scan.scheduler.queue.retry_log_publication import safe_report_retry_log_failure as _report_retry_failure
from Virus_Scan.scheduler.queue.retry_policy_callback_safety import (
    safe_is_retryable_failure as _retryable_failure,
    safe_retry_max as _retry_max,
)
from Virus_Scan.scheduler.queue.retry_policy_execution import (
    apply_retry_failure_integrity,
    clear_retry_integrity_for_next_attempt,
    persist_retry_integrity,
    run_retry_worker_attempt,
)
from Virus_Scan.scheduler.queue.retry_worker_contract import safe_worker_result_mapping as _worker_result_mapping


@dataclass(frozen=True)
class RetryRunState:
    last_file: object
    last_result: object
    attempts: int
    max_retries: int
    retry_failures: tuple[dict[str, object], ...]


def run_retry_attempt_loop(
    *,
    path: object,
    prev: object,
    use_signal_timeout: bool,
    worker_once: Callable[..., object],
    retry_max: Callable[[object], int],
    is_retryable_failure: Callable[[object], bool],
    clear_integrity: Callable[[object], object],
    report_retry_log_failure: Callable[[BaseException, Mapping[str, object]], object],
) -> RetryRunState:
    """Run worker attempts until the retry policy reaches a terminal state."""
    attempts = 0
    last_file = path
    last_result = None
    retry_failures: list[dict[str, object]] = []
    max_retries = _retry_max(
        retry_max=retry_max,
        prev=prev,
        path=path,
        retry_failures=retry_failures,
    )
    while True:
        attempts += 1
        last_file, last_result = run_retry_worker_attempt(
            worker_once=worker_once,
            path=path,
            prev=prev,
            use_signal_timeout=use_signal_timeout,
            attempt=attempts,
            retry_failures=retry_failures,
        )
        retryable_now = _retryable_failure(
            is_retryable_failure=is_retryable_failure,
            value=last_result,
            path=last_file,
            attempt=attempts,
            retry_failures=retry_failures,
        )
        if not retryable_now or attempts > max_retries:
            break
        clear_retry_integrity_for_next_attempt(
            clear_integrity=clear_integrity,
            report_retry_log_failure=report_retry_log_failure,
            retry_log_failure_reporter=_report_retry_failure,
            path=path,
            attempt=attempts,
            retry_failures=retry_failures,
        )
    return RetryRunState(
        last_file=last_file,
        last_result=last_result,
        attempts=attempts,
        max_retries=max_retries,
        retry_failures=tuple(retry_failures),
    )


def build_retry_terminal_result(
    *,
    state: RetryRunState,
    get_integrity: Callable[[object], Mapping[str, object]],
    is_retryable_failure: Callable[[object], bool],
    set_integrity: Callable[[object, Mapping[str, object]], object],
    report_retry_log_failure: Callable[[BaseException, Mapping[str, object]], object],
) -> object:
    """Build and persist terminal retry integrity for the completed attempts."""
    retry_failures = list(state.retry_failures)
    result = _worker_result_mapping(
        last_result=state.last_result,
        path=state.last_file,
        attempt=state.attempts,
        retry_failures=retry_failures,
    )
    integrity = dict(
        _read_result_integrity(
            result=result,
            path=state.last_file,
            attempt=state.attempts,
            get_integrity=get_integrity,
            retry_failures=retry_failures,
        )
        or {}
    )
    if state.attempts > 1:
        result["file_retried"] = True
        integrity["file_retried"] = True
    integrity["file_retry_attempts"] = state.attempts
    final_retryable = _retryable_failure(
        is_retryable_failure=is_retryable_failure,
        value=result,
        path=state.last_file,
        attempt=state.attempts,
        retry_failures=retry_failures,
    )
    apply_retry_failure_integrity(integrity=integrity, retry_failures=retry_failures)
    if final_retryable and state.attempts > state.max_retries:
        integrity["file_failed"] = True
        integrity["file_retry_exhausted"] = True
    result["scan_integrity"] = integrity
    persist_retry_integrity(
        set_integrity=set_integrity,
        report_retry_log_failure=report_retry_log_failure,
        persistence_failure_recorder=record_retry_integrity_persistence_failure,
        result=result,
        integrity=integrity,
        path=state.last_file,
        attempt=state.attempts,
    )
    return result


__all__ = ("RetryRunState", "build_retry_terminal_result", "run_retry_attempt_loop")
