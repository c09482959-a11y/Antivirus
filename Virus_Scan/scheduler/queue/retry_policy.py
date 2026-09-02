"""Queue-owned raw file retry policy.

Retry bookkeeping is queue policy, not execution ownership. The policy records
clear-integrity failures as replay-visible retry evidence instead of treating
retry cleanup failures as clean scans.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.queue import retry_integrity_access as _retry_integrity_access
from Virus_Scan.scheduler.queue import retry_integrity_persistence as _retry_integrity_persistence
from Virus_Scan.scheduler.queue import retry_log_publication as _retry_log_publication
from Virus_Scan.scheduler.queue import retry_policy_callback_safety as _retry_policy_callback_safety

_RETRY_POLICY_BOUNDARY_MODULES = (
    _retry_policy_callback_safety,
    _retry_integrity_access,
    _retry_integrity_persistence,
    _retry_log_publication,
)

from Virus_Scan.scheduler.queue.retry_policy_steps import (
    build_retry_terminal_result,
    run_retry_attempt_loop,
)


@dataclass(frozen=True, slots=True)
class RetryPolicyRequest:
    """Internal request for one deterministic raw-file retry run."""

    path: object
    prev: object
    use_signal_timeout: bool
    worker_once: Callable[..., object]
    retry_max: Callable[[object], int]
    is_retryable_failure: Callable[[object], bool]
    clear_integrity: Callable[[object], object]
    get_integrity: Callable[[object], Mapping[str, object]]
    set_integrity: Callable[[object, Mapping[str, object]], object]
    report_retry_log_failure: Callable[[BaseException, Mapping[str, object]], object]


def run_file_with_retry(request: RetryPolicyRequest) -> object:
    """Run a file through the canonical immutable retry request."""
    state = run_retry_attempt_loop(
        path=request.path,
        prev=request.prev,
        use_signal_timeout=request.use_signal_timeout,
        worker_once=request.worker_once,
        retry_max=request.retry_max,
        is_retryable_failure=request.is_retryable_failure,
        clear_integrity=request.clear_integrity,
        report_retry_log_failure=request.report_retry_log_failure,
    )
    result = build_retry_terminal_result(
        state=state,
        get_integrity=request.get_integrity,
        is_retryable_failure=request.is_retryable_failure,
        set_integrity=request.set_integrity,
        report_retry_log_failure=request.report_retry_log_failure,
    )
    return state.last_file, result



__all__ = (
    'RetryPolicyRequest',
    'run_file_with_retry',
)
