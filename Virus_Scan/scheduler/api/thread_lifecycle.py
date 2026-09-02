"""Public scheduler API for deterministic thread executor lifecycle helpers.

Phase 8 centralizes ThreadPoolExecutor ownership so scheduler code does not
silently leave queued work alive after cancellation, timeout, or exception
paths.  This module intentionally owns only local scheduler thread pools; it
is not a generic facade and it does not start background work at
import time.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from contextvars import copy_context
import math
from typing import Callable, Literal, Optional, Self, Set

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

_SCHEDULER_THREAD_POOL_MAX_WORKERS_EXACT_INTEGER = "scheduler thread pool max_workers must be an exact integer"
_SCHEDULER_THREAD_POOL_ALREADY_ACTIVE = "scheduler thread pool is already active"
_SCHEDULER_THREAD_POOL_NOT_ACTIVE = "scheduler thread pool is not active"
_SCHEDULER_THREAD_POOL_THREAD_NAME_PREFIX_UNSUPPORTED_TYPE = (
    "scheduler thread pool thread_name_prefix rejects unsupported value type "
)
_SCHEDULER_THREAD_POOL_CANCEL_ON_ERROR_UNSUPPORTED_TYPE = (
    "scheduler thread pool cancel_on_error rejects unsupported value type "
)


class SchedulerThreadPool:
    """Explicit lifecycle owner for scheduler local thread pools.

    The owner tracks submitted futures and applies deterministic shutdown
    semantics on exit.  Normal exits wait for running work.  Exceptional exits
    cancel pending futures first and then wait for already-running work to
    finish, matching ThreadPoolExecutor's cooperative cancellation contract.
    """

    def __init__(self, *, max_workers: int, thread_name_prefix: str = "", cancel_on_error: bool = True) -> None:
        if max_workers is None:
            exact_max_workers = 1
        elif type(max_workers) is bool:
            exact_max_workers = 1
        elif type(max_workers) is int:
            exact_max_workers = max(1, max_workers)
        elif type(max_workers) is float and math.isfinite(max_workers) and max_workers.is_integer():
            exact_max_workers = max(1, int(max_workers))
        elif type(max_workers) is float:
            raise ValueError(_SCHEDULER_THREAD_POOL_MAX_WORKERS_EXACT_INTEGER)
        elif type(max_workers) is str:
            max_workers_text = str.__str__(max_workers).strip()
            if max_workers_text == "":
                exact_max_workers = 1
            else:
                try:
                    exact_max_workers = max(1, int(max_workers_text, 10))
                except ValueError as exc:
                    raise ValueError(_SCHEDULER_THREAD_POOL_MAX_WORKERS_EXACT_INTEGER) from exc
        else:
            raise TypeError(
                "scheduler thread pool max_workers rejects unsupported value type "
                + no_hook_type_name(max_workers)
            )
        self.max_workers = exact_max_workers
        self.thread_name_prefix = _exact_thread_name_prefix(thread_name_prefix)
        self.cancel_on_error = _exact_cancel_on_error(cancel_on_error)
        self._executor: Optional[ThreadPoolExecutor] = None
        self._futures: Set[Future] = set()
        self._closed = False

    def __enter__(self) -> Self:
        if self._executor is not None and not self._closed:
            raise RuntimeError(_SCHEDULER_THREAD_POOL_ALREADY_ACTIVE)
        self._closed = False
        self._futures.clear()
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix=self.thread_name_prefix,
        )
        return self

    def submit(self, fn: Callable[..., object], /, *args: object, **kwargs: object) -> Future:
        if self._executor is None or self._closed:
            raise RuntimeError(_SCHEDULER_THREAD_POOL_NOT_ACTIVE)
        ctx = copy_context()
        fut = self._executor.submit(ctx.run, fn, *args, **kwargs)
        self._futures.add(fut)
        fut.add_done_callback(self._futures.discard)
        return fut

    def cancel_pending(self) -> int:
        cancelled = 0
        for fut in list(self._futures):
            if not fut.done() and fut.cancel():
                cancelled += 1
        return cancelled

    def __exit__(self, exc_type: object, exc: object, tb: object) -> Literal[False]:
        self._closed = True
        if exc_type is not None and self.cancel_on_error:
            self.cancel_pending()
        if self._executor is not None:
            # cancel_futures is available on supported Python versions and only
            # cancels not-yet-started work; running scans still finish cleanly.
            self._executor.shutdown(wait=True, cancel_futures=(exc_type is not None and self.cancel_on_error))
        self._executor = None
        self._futures.clear()
        return False




def _exact_thread_name_prefix(value: object) -> str:
    if value is None:
        return ""
    if type(value) is str:
        return str.__str__(value)
    raise TypeError(
        _SCHEDULER_THREAD_POOL_THREAD_NAME_PREFIX_UNSUPPORTED_TYPE
        + no_hook_type_name(value)
    )


def _exact_cancel_on_error(value: object) -> bool:
    if value is None:
        return True
    if type(value) is bool:
        return value
    if type(value) is int:
        return value != 0
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text == "":
            return True
        if text in {"1", "true", "yes", "on", "error", "cancel"}:
            return True
        if text in {"0", "false", "no", "off", "keep"}:
            return False
    raise TypeError(
        _SCHEDULER_THREAD_POOL_CANCEL_ON_ERROR_UNSUPPORTED_TYPE
        + no_hook_type_name(value)
    )


__all__ = ("SchedulerThreadPool",)
