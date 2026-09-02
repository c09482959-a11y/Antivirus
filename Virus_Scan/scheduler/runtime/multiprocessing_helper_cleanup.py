"""Bounded cleanup for scheduler-owned multiprocessing helper processes."""
from __future__ import annotations

import os
import signal
import time
from multiprocessing import forkserver as _mp_forkserver
from multiprocessing import resource_tracker as _mp_resource_tracker
from typing import Protocol, cast

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS

_WAITPID_NOHANG = getattr(os, "WNOHANG", 0)
_SCHEDULER_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)


class _ForkserverOwner(Protocol):
    _forkserver_alive_fd: int | None
    _forkserver_pid: int | None
    _forkserver_address: str | None


class _ResourceTrackerOwner(Protocol):
    _fd: int | None
    _pid: int | None
    _exitcode: int | None


def _scheduler_helper_pid(owner: object, *names: str) -> int | None:
    """Return a live helper PID from a stdlib multiprocessing owner object."""
    for name in names:
        try:
            value = getattr(owner, name, None)
        except RECOVERABLE_RUNTIME_ERRORS:
            continue
        if type(value) is int and value > 0:
            return value
    return None


def _close_scheduler_helper_fd(fd: int | None) -> str:
    """Close an owned multiprocessing helper fd without invoking private stops."""
    if fd is None:
        return "no_helper_fd"
    try:
        os.close(fd)
    except OSError:
        return "helper_fd_already_closed"
    return "helper_fd_closed"


def _reap_scheduler_helper_pid(pid: int | None) -> str:
    """Reap an owned helper PID only when it is immediately available."""
    if pid is None or os.name == "nt":
        return "helper_pid_not_reaped"
    try:
        reaped_pid, status = os.waitpid(pid, _WAITPID_NOHANG)
    except ChildProcessError:
        return "helper_pid_not_child"
    except RECOVERABLE_RUNTIME_ERRORS:
        return "helper_pid_reap_unavailable"
    if reaped_pid == pid:
        return f"helper_pid_reaped_{status}"
    return "helper_pid_still_owned"


def _terminate_scheduler_helper_pid(pid: int | None) -> str:
    """Best-effort bounded termination for scheduler-owned stdlib helper PIDs."""
    if pid is None:
        return "no_helper_pid"
    if os.name == "nt":
        return "helper_pid_unterminated_on_windows"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return "helper_pid_already_exited"
    except RECOVERABLE_RUNTIME_ERRORS:
        return "helper_pid_sigterm_unavailable"
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        reap_result = _reap_scheduler_helper_pid(pid)
        if reap_result.startswith("helper_pid_reaped") or reap_result == "helper_pid_not_child":
            return reap_result
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "helper_pid_terminated"
        except RECOVERABLE_RUNTIME_ERRORS:
            break
        time.sleep(0.01)
    try:
        os.kill(pid, _SCHEDULER_SIGKILL)
    except ProcessLookupError:
        return "helper_pid_terminated"
    except RECOVERABLE_RUNTIME_ERRORS:
        return "helper_pid_sigkill_unavailable"
    reap_result = _reap_scheduler_helper_pid(pid)
    if reap_result.startswith("helper_pid_reaped") or reap_result == "helper_pid_not_child":
        return reap_result
    return "helper_pid_killed"


def _release_scheduler_forkserver_owner(owner: object) -> tuple[str, ...]:
    """Detach stdlib forkserver owner state after bounded helper termination."""
    forkserver_pid = _scheduler_helper_pid(owner, "_forkserver_pid")
    alive_fd = getattr(owner, "_forkserver_alive_fd", None)
    address = getattr(owner, "_forkserver_address", None)
    results: list[str] = ["forkserver"]
    results.append(f"forkserver_{_close_scheduler_helper_fd(alive_fd if type(alive_fd) is int else None)}")
    results.append(f"forkserver_{_terminate_scheduler_helper_pid(forkserver_pid)}")
    forkserver_owner = cast(_ForkserverOwner, owner)
    try:
        forkserver_owner._forkserver_alive_fd = None
        forkserver_owner._forkserver_pid = None
        forkserver_owner._forkserver_address = None
    except RECOVERABLE_RUNTIME_ERRORS:
        results.append("forkserver_state_reset_unavailable")
    if type(address) is str and not address.startswith("\0"):
        try:
            os.unlink(address)
        except FileNotFoundError:
            results.append("forkserver_address_already_unlinked")
        except RECOVERABLE_RUNTIME_ERRORS:
            results.append("forkserver_address_unlink_unavailable")
    return tuple(results)


def shutdown_scheduler_multiprocessing_context_runtime() -> tuple[str, ...]:
    """Stop scheduler-owned multiprocessing helpers without blocking exit."""
    stopped: list[str] = []
    try:
        forkserver_owner = _mp_forkserver._forkserver
    except RECOVERABLE_RUNTIME_ERRORS:
        stopped.append("forkserver_shutdown_unavailable")
    else:
        stopped.extend(_release_scheduler_forkserver_owner(forkserver_owner))

    try:
        tracker_owner = _mp_resource_tracker._resource_tracker
    except RECOVERABLE_RUNTIME_ERRORS:
        stopped.append("resource_tracker_shutdown_unavailable")
    else:
        tracker_pid = _scheduler_helper_pid(tracker_owner, "_pid")
        tracker_fd = getattr(tracker_owner, "_fd", None)
        stopped.append("resource_tracker")
        stopped.append(
            f"resource_tracker_{_close_scheduler_helper_fd(tracker_fd if type(tracker_fd) is int else None)}"
        )
        stopped.append(
            f"resource_tracker_{_terminate_scheduler_helper_pid(tracker_pid)}"
        )
        typed_tracker_owner = cast(_ResourceTrackerOwner, tracker_owner)
        try:
            typed_tracker_owner._fd = None
            typed_tracker_owner._pid = None
            typed_tracker_owner._exitcode = None
        except RECOVERABLE_RUNTIME_ERRORS:
            stopped.append("resource_tracker_state_reset_unavailable")

    return tuple(stopped)


__all__ = ("shutdown_scheduler_multiprocessing_context_runtime",)
