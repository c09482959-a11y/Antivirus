"""Canonical scheduler multiprocessing context ownership.

Owns multiprocessing context selection without mutating queue, worker, replay,
or evidence state.  Scheduler execution modules consume the context produced
here instead of selecting a platform default directly.
"""
from __future__ import annotations

from dataclasses import dataclass
import multiprocessing as mp
import os
from Virus_Scan.runtime.api import runtime_worker_shared_persistence_writes_disabled
from typing import TYPE_CHECKING

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.runtime.multiprocessing_helper_cleanup import (
    shutdown_scheduler_multiprocessing_context_runtime,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass(frozen=True, slots=True)
class MultiprocessingContextSnapshot:
    start_method: str


def available_scheduler_start_methods() -> tuple[str, ...]:
    """Return multiprocessing start methods visible to scheduler runtime."""
    try:
        return tuple(method for method in mp.get_all_start_methods() if type(method) is str and method)
    except RECOVERABLE_RUNTIME_ERRORS:
        return ("spawn",)


def choose_scheduler_start_method(
    *,
    preferred: str | None = None,
    platform_name: str | None = None,
    available_start_methods: Iterable[str] | None = None,
) -> str:
    """Choose a scheduler-owned start method without using fork.

    ``fork`` is intentionally avoided because Python warns that forking from a
    multi-threaded scheduler parent can deadlock children.  ``forkserver`` is
    preferred on POSIX when available because it avoids forking from the
    already-threaded scheduler process.  ``spawn`` remains the deterministic
    cross-platform default.
    """
    if available_start_methods is None:
        available = available_scheduler_start_methods()
    elif type(available_start_methods) in {tuple, list}:
        available = tuple(method for method in available_start_methods if type(method) is str and method)
    else:
        available = ("spawn",)
    allowed = tuple(method for method in available if method != "fork")
    if type(preferred) is str and preferred in allowed:
        return preferred

    platform = platform_name if type(platform_name) is str else os.name
    if platform != "nt" and "forkserver" in allowed:
        return "forkserver"
    if "spawn" in allowed:
        return "spawn"
    if allowed:
        return allowed[0]
    return "spawn"


def capture_multiprocessing_context() -> MultiprocessingContextSnapshot:
    method = choose_scheduler_start_method()
    return MultiprocessingContextSnapshot(method)


def get_scheduler_multiprocessing_context(*, preferred: str | None = None) -> object:
    """Return the scheduler-owned multiprocessing context.

    The function does not call ``set_start_method`` and does not mutate global
    multiprocessing defaults.  The returned context is constructor/context owned
    by scheduler runtime and can be passed into worker/queue owners explicitly.

    The provider uses the same non-fork start-method policy as
    ``choose_scheduler_start_method`` unless a safe explicit preference is
    supplied.  On POSIX this prefers ``forkserver`` when available so spawned
    scheduler children do not re-import a ``python -m pytest`` parent module and
    recursively enter test collection/execution.  The explicit shutdown owner
    below tears down forkserver/resource-tracker helpers at the scheduler runtime
    boundary.
    """
    requested = preferred if type(preferred) is str and preferred else None
    method = choose_scheduler_start_method(preferred=requested)
    try:
        return mp.get_context(method)
    except RECOVERABLE_RUNTIME_ERRORS:
        recovery_method = choose_scheduler_start_method(preferred="spawn", available_start_methods=("spawn",))
        return mp.get_context(recovery_method)


def shutdown_scheduler_multiprocessing_context_at_exit() -> tuple[str, ...]:
    """Non-blocking scheduler helper cleanup safe for explicit shutdown callers."""
    return shutdown_scheduler_multiprocessing_context_runtime()


def scheduler_worker_shared_persistence_writes_disabled(env: object=None) -> bool:
    """Return True when the current process is a scheduler worker/shard.

    The canonical process-environment identity check is runtime-owned; the
    scheduler API exposes the scheduler-facing public name while consuming that
    owner directly.
    """
    return runtime_worker_shared_persistence_writes_disabled(env)


__all__ = (
    "MultiprocessingContextSnapshot",
    "available_scheduler_start_methods",
    "capture_multiprocessing_context",
    "choose_scheduler_start_method",
    "get_scheduler_multiprocessing_context",
    "scheduler_worker_shared_persistence_writes_disabled",
    "shutdown_scheduler_multiprocessing_context_at_exit",
    "shutdown_scheduler_multiprocessing_context_runtime",
)
