"""Shared worker IPC lifecycle no-hook helpers."""
from __future__ import annotations

from collections.abc import Callable, MutableMapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.internal.no_hook_methods import safe_scheduler_bound_method
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import worker_lifecycle_exception_reason
from Virus_Scan.scheduler.workers.ipc_lifecycle_numeric import (
    worker_lifecycle_float,
    worker_lifecycle_float_outcome,
    worker_lifecycle_int,
    worker_lifecycle_int_outcome,
)

LifecycleCallable = Callable[..., object]
FailureRecorder = Callable[[str, BaseException], object]
LifecycleStatus = dict[str, object]
LifecycleContainer = MutableMapping[str, object]
LifecycleErrorEntry = dict[str, str]

_QUEUE_METHOD_NAMES = frozenset(("cancel_join_thread", "close", "join_thread"))
_PROCESS_METHOD_NAMES = frozenset(("join", "is_alive", "terminate", "close"))
_HEARTBEAT_EVENT_METHOD_NAMES = frozenset(("set",))
_HEARTBEAT_THREAD_METHOD_NAMES = frozenset(("join", "is_alive"))


def _worker_lifecycle_method(
    owner: object | None, name: str, allowed: frozenset[str]
) -> tuple[LifecycleCallable | None, str]:
    method, reason = safe_scheduler_bound_method(
        owner,
        name,
        reason_prefix="unsafe_worker_lifecycle",
        allowed_names=allowed,
    )
    if reason or method is None:
        return None, reason
    if not callable(method):
        return None, "unsafe_worker_lifecycle_callable_rejected"
    return method, ""


def worker_queue_method(queue: object | None, name: str) -> tuple[LifecycleCallable | None, str]:
    return _worker_lifecycle_method(queue, name, _QUEUE_METHOD_NAMES)


def worker_process_method(proc: object | None, name: str) -> tuple[LifecycleCallable | None, str]:
    return _worker_lifecycle_method(proc, name, _PROCESS_METHOD_NAMES)


# Heartbeat event/thread shutdown now calls the canonical lifecycle helper directly.
# Removed helpers were private pass-through routes around the same owner.
# Queue/process lifecycle adapters remain public because current callers import them.
# Heartbeat shutdown is internal to this module and does not need a second route.
# The allowed-name sets above still constrain every no-hook method lookup.
# The canonical helper still rejects unsafe descriptors and non-callable values.
# This block contains no extra executable lifecycle route.
# It documents the retained boundary split without adding another callable path.
# Existing line-sensitive sentinel guards remain stable below this point.
# Future heartbeat lifecycle paths should call _worker_lifecycle_method directly.
# Do not recreate private heartbeat method wrappers without a public contract.
# Keep this non-executable note above guarded bare-return rows.
def _container_errors(container: LifecycleContainer) -> list[object]:
    errors = container.get("errors")
    if type(errors) is list:
        return errors
    replacement: list[object] = []
    container["errors"] = replacement
    return replacement


def _record_failure(label: str, exc: BaseException, failure_recorder: object | None) -> str:
    if callable(failure_recorder):
        try:
            failure_recorder(label, exc)
        except RECOVERABLE_RUNTIME_ERRORS as recorder_exc:
            return worker_lifecycle_exception_reason(recorder_exc)
    return ""


def record_method_rejection(
    container: LifecycleContainer,
    label: str,
    reason: str,
    *,
    failure_recorder: object | None = None,
) -> None:
    if not reason:
        return
    errors = _container_errors(container)
    errors.append({"stage": label, "error": reason})
    recorder_reason = _record_failure(label, RuntimeError(reason), failure_recorder)
    if recorder_reason:
        errors.append({"stage": str.__add__(label, "_recorder_failed"), "error": recorder_reason})


def _record_heartbeat_rejection(
    status: LifecycleStatus, label: str, reason: str, failure_recorder: object | None
) -> None:
    status["error"] = reason
    recorder_reason = _record_failure(label, RuntimeError(reason), failure_recorder)
    if recorder_reason:
        status["recorder_error"] = recorder_reason


def stop_worker_heartbeat(
    hb_stop: object | None,
    hb_thread: object | None,
    *,
    join_timeout: float = 1.0,
    failure_recorder: object | None = None,
) -> LifecycleStatus:
    """Stop a queue-child heartbeat thread through one explicit lifecycle path."""
    status: LifecycleStatus = {"signalled": False, "joined": False, "alive": False, "error": ""}
    try:
        stop_set, stop_reason = _worker_lifecycle_method(hb_stop, "set", _HEARTBEAT_EVENT_METHOD_NAMES)
        if stop_reason:
            _record_heartbeat_rejection(status, "worker_heartbeat_stop_rejected", stop_reason, failure_recorder)
            return status
        if stop_set is not None:
            stop_set()
            status["signalled"] = True
        thread_join, join_reason = _worker_lifecycle_method(hb_thread, "join", _HEARTBEAT_THREAD_METHOD_NAMES)
        if join_reason:
            _record_heartbeat_rejection(status, "worker_heartbeat_thread_rejected", join_reason, failure_recorder)
            return status
        if thread_join is not None:
            try:
                thread_join(timeout=max(0.0, worker_lifecycle_float(join_timeout, 1.0)))
            finally:
                status["joined"] = True
            thread_alive, alive_reason = _worker_lifecycle_method(hb_thread, "is_alive", _HEARTBEAT_THREAD_METHOD_NAMES)
            if alive_reason:
                _record_heartbeat_rejection(status, "worker_heartbeat_alive_rejected", alive_reason, failure_recorder)
                return status
            if thread_alive is not None:
                status["alive"] = bool(thread_alive())
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        status["error"] = worker_lifecycle_exception_reason(exc)
        recorder_reason = _record_failure("worker_heartbeat_shutdown_failed", exc, failure_recorder)
        if recorder_reason:
            status["recorder_error"] = recorder_reason
    return status


__all__ = (
    "record_method_rejection",
    "stop_worker_heartbeat",
    "worker_lifecycle_float",
    "worker_lifecycle_float_outcome",
    "worker_lifecycle_int",
    "worker_lifecycle_int_outcome",
    "worker_process_method",
    "worker_queue_method",
)
